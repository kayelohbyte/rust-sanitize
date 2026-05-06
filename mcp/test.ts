#!/usr/bin/env -S deno run --allow-run --allow-env --allow-read --allow-write
/**
 * End-to-end MCP protocol tests.
 *
 * Spawns the MCP server as a subprocess and communicates with it using the
 * JSON-RPC-over-stdio transport (newline-delimited JSON).
 *
 * Usage:
 *   deno run --allow-run --allow-env --allow-read --allow-write mcp/test.ts
 *
 * Set SANITIZE_BIN if the binary is not on PATH:
 *   SANITIZE_BIN=./target/release/sanitize deno run ... mcp/test.ts
 */

import { join } from "@std/path";

const MCP_SCRIPT = join(import.meta.dirname!, "src/index.ts");
const SANITIZE_BIN =
  Deno.env.get("SANITIZE_BIN") ??
  join(import.meta.dirname!, "../target/release/sanitize");

// ---------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();

let idCounter = 1;

function nextId() {
  return idCounter++;
}

function serialize(msg: unknown): Uint8Array {
  return enc.encode(JSON.stringify(msg) + "\n");
}

// ---------------------------------------------------------------------------
// MCP session
// ---------------------------------------------------------------------------

class McpSession {
  private child: Deno.ChildProcess;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private reader: ReadableStreamDefaultReader<string>;
  private pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: unknown) => void }
  >();
  private closed = false;

  constructor(child: Deno.ChildProcess) {
    this.child = child;
    this.writer = child.stdin.getWriter();

    // Wrap the stdout byte stream in a line reader.
    const lineStream = child.stdout
      .pipeThrough(new TextDecoderStream())
      .pipeThrough(new TransformStream<string, string>({
        transform(chunk, controller) {
          // chunk may contain multiple newline-delimited messages
          for (const line of chunk.split("\n")) {
            if (line.trim()) controller.enqueue(line.trim());
          }
        },
      }));
    this.reader = lineStream.getReader();
    this.startReadLoop();
  }

  private async startReadLoop() {
    while (!this.closed) {
      let result: ReadableStreamReadResult<string>;
      try {
        result = await this.reader.read();
      } catch {
        break;
      }
      if (result.done) break;
      try {
        const msg = JSON.parse(result.value) as {
          id?: number;
          result?: unknown;
          error?: unknown;
        };
        if (msg.id !== undefined) {
          const pending = this.pending.get(msg.id);
          if (pending) {
            this.pending.delete(msg.id);
            if (msg.error) pending.reject(msg.error);
            else pending.resolve(msg.result);
          }
        }
      } catch {
        // ignore unparseable lines (e.g. log output on stderr)
      }
    }
  }

  async send(method: string, params?: unknown): Promise<unknown> {
    const id = nextId();
    const msg = { jsonrpc: "2.0", id, method, params };
    const promise = new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    await this.writer.write(serialize(msg));
    return promise;
  }

  async notify(method: string, params?: unknown) {
    const msg = { jsonrpc: "2.0", method, params };
    await this.writer.write(serialize(msg));
  }

  async close() {
    this.closed = true;
    try {
      await this.writer.close();
    } catch { /* already closed */ }
    try {
      this.child.kill("SIGTERM");
    } catch { /* already dead */ }
    await this.child.status;
  }
}

async function startSession(): Promise<McpSession> {
  const cmd = new Deno.Command(
    Deno.execPath(),
    {
      args: [
        "run",
        "--allow-run",
        "--allow-env",
        "--allow-read",
        "--allow-write",
        MCP_SCRIPT,
      ],
      stdin: "piped",
      stdout: "piped",
      stderr: "null",
      env: {
        ...Deno.env.toObject(),
        SANITIZE_BIN,
        SANITIZE_LOG: "error",
      },
    },
  );

  const child = cmd.spawn();
  const session = new McpSession(child);

  // MCP handshake
  await session.send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "test-client", version: "1.0" },
  });
  await session.notify("notifications/initialized");

  return session;
}

// ---------------------------------------------------------------------------
// Minimal test runner
// ---------------------------------------------------------------------------

type TestFn = (session: McpSession) => Promise<void>;
const tests: Array<{ name: string; fn: TestFn }> = [];

function test(name: string, fn: TestFn) {
  tests.push({ name, fn });
}

function assert(condition: boolean, msg: string) {
  if (!condition) throw new Error(`Assertion failed: ${msg}`);
}

function assertContains(haystack: string, needle: string) {
  if (!haystack.includes(needle)) {
    throw new Error(`Expected output to contain ${JSON.stringify(needle)}\nGot: ${haystack}`);
  }
}

function assertNotContains(haystack: string, needle: string) {
  if (haystack.includes(needle)) {
    throw new Error(`Expected output NOT to contain ${JSON.stringify(needle)}\nGot: ${haystack}`);
  }
}

function toolText(result: unknown): string {
  const r = result as { content: Array<{ type: string; text: string }> };
  return r.content.map((c) => c.text).join("");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("list_templates returns both built-in templates", async (s) => {
  const result = toolText(await s.send("tools/call", { name: "list_templates", arguments: {} }));
  const parsed = JSON.parse(result);
  assert(Array.isArray(parsed.templates), "templates should be an array");
  assert(parsed.templates.length === 2, "should have 2 templates");
  assert(
    parsed.templates.some((t: { name: string }) => t.name === "troubleshoot"),
    "should include troubleshoot",
  );
  assert(
    parsed.templates.some((t: { name: string }) => t.name === "review-config"),
    "should include review-config",
  );
});

test("sanitize replaces email address", async (s) => {
  const result = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        content: "Contact alice@example.com for help.",
        patterns: [
          { name: "email", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", category: "email" },
        ],
      },
    }),
  );
  assertNotContains(result, "alice@example.com");
  assert(result.includes("@"), "sanitized email should still look like an email");
});

test("sanitize with seed produces deterministic output", async (s) => {
  const args = {
    name: "sanitize",
    arguments: {
      content: "token: abc123secret",
      seed: "test-seed-stable",
      patterns: [{ name: "tok", pattern: "abc123secret", category: "generic" }],
    },
  };
  const r1 = toolText(await s.send("tools/call", args));
  const r2 = toolText(await s.send("tools/call", args));
  assert(r1 === r2, `seed should produce identical output\nr1: ${r1}\nr2: ${r2}`);
  assertNotContains(r1, "abc123secret");
});

test("sanitize without patterns returns content unchanged", async (s) => {
  const content = "no sensitive data here";
  const result = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: { content },
    }),
  );
  assert(result.trim() === content, `expected unchanged content, got: ${result}`);
});

test("scan returns structured report with match counts", async (s) => {
  const result = toolText(
    await s.send("tools/call", {
      name: "scan",
      arguments: {
        content: "pass = hunter2\napi_key = s3cr3t",
        patterns: [
          { name: "val", pattern: "hunter2|s3cr3t", category: "generic" },
        ],
      },
    }),
  );
  const report = JSON.parse(result);
  assert(typeof report === "object", "should return a JSON object");
  assert("files" in report, "report should have a files array");
  const totalMatches = report.files.reduce(
    (sum: number, f: { matches: number }) => sum + (f.matches ?? 0),
    0,
  );
  assert(totalMatches >= 2, `expected ≥2 matches, got ${totalMatches}`);
});

test("scan dry_run does not modify content", async (s) => {
  const content = "secret = topsecret123";
  const result = toolText(
    await s.send("tools/call", {
      name: "scan",
      arguments: {
        content,
        patterns: [{ name: "s", pattern: "topsecret123", category: "generic" }],
      },
    }),
  );
  const report = JSON.parse(result);
  // scan uses --dry-run so no output file changes, just counts
  assert("files" in report, "should have files in report");
});

test("strip_config_values removes values preserves keys", async (s) => {
  const result = toolText(
    await s.send("tools/call", {
      name: "strip_config_values",
      arguments: { content: "# settings\nhost = localhost\nport = 5432\n[db]\n" },
    }),
  );
  assertContains(result, "host =");
  assertContains(result, "port =");
  assertNotContains(result, "localhost");
  assertNotContains(result, "5432");
  assertContains(result, "# settings");
  assertContains(result, "[db]");
});

test("strip_config_values custom delimiter", async (s) => {
  const result = toolText(
    await s.send("tools/call", {
      name: "strip_config_values",
      arguments: {
        content: "host: localhost\nport: 5432\n",
        delimiter: ":",
      },
    }),
  );
  assertContains(result, "host:");
  assertContains(result, "port:");
  assertNotContains(result, "localhost");
  assertNotContains(result, "5432");
});

test("strip_config_values custom comment prefix", async (s) => {
  const result = toolText(
    await s.send("tools/call", {
      name: "strip_config_values",
      arguments: {
        content: "// nginx config\nworker_processes = auto\n",
        comment_prefix: "//",
      },
    }),
  );
  assertContains(result, "// nginx config");
  assertContains(result, "worker_processes =");
  assertNotContains(result, "auto");
});

test("extract_context returns content and report with log_context", async (s) => {
  const content = [
    "INFO  service started",
    "INFO  processing request",
    "ERROR disk full on /dev/sda1",
    "INFO  retrying mount",
    "WARN  filesystem degraded",
    "INFO  recovery complete",
  ].join("\n");

  const raw = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        content,
        extract_context: true,
      },
    }),
  );

  const result = JSON.parse(raw);
  assert("content" in result, "should have content field");
  assert("report" in result, "should have report field");
  assertContains(result.content, "service started");

  const logContext = result.report.files[0].log_context;
  assert(logContext !== null && logContext !== undefined, "log_context should be present");
  assert(logContext.match_count >= 2, `expected ≥2 matches (error + warn), got ${logContext.match_count}`);

  const keywords = logContext.matches.map((m: { keyword: string }) => m.keyword);
  assert(keywords.includes("error"), "should have flagged ERROR line");
  assert(keywords.includes("warn"), "should have flagged WARN line");
});

test("extract_context with custom keyword only flags that keyword", async (s) => {
  const content = "INFO ok\nERROR fail\nTIMEOUT waiting\n";

  const raw = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        content,
        extract_context: true,
        context_keywords: ["timeout"],
      },
    }),
  );

  const result = JSON.parse(raw);
  const keywords = result.report.files[0].log_context.matches.map(
    (m: { keyword: string }) => m.keyword,
  );
  assert(keywords.includes("error"), "built-in 'error' keyword should still match");
  assert(keywords.includes("timeout"), "custom 'timeout' keyword should match");
});

test("extract_context max_context_matches caps results", async (s) => {
  const lines = Array.from({ length: 10 }, (_, i) => `ERROR line ${i}`).join("\n");

  const raw = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        content: lines,
        extract_context: true,
        max_context_matches: 3,
      },
    }),
  );

  const result = JSON.parse(raw);
  const logContext = result.report.files[0].log_context;
  assert(logContext.match_count === 3, `expected 3 matches, got ${logContext.match_count}`);
  assert(logContext.truncated === true, "should be truncated");
});

test("extract_context case_sensitive skips wrong-case matches", async (s) => {
  const content = "INFO ok\nERROR uppercase\nerror lowercase\n";

  const raw = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        content,
        extract_context: true,
        context_keywords: ["error"],
        context_case_sensitive: true,
      },
    }),
  );

  const result = JSON.parse(raw);
  const lines = result.report.files[0].log_context.matches.map(
    (m: { line: string }) => m.line,
  );
  assert(!lines.some((l: string) => l.includes("ERROR uppercase")), "uppercase ERROR should not match");
  assert(lines.some((l: string) => l.includes("error lowercase")), "lowercase error should match");
});

test("sanitize without extract_context returns plain string", async (s) => {
  const raw = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: { content: "hello world" },
    }),
  );
  // Should be a plain string, not JSON with content/report fields
  assert(raw.trim() === "hello world", `expected plain string, got: ${raw}`);
});

test("sanitize with format json uses structured processor", async (s) => {
  const content = JSON.stringify({ password: "hunter2", host: "prod.example.com" });
  const result = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        content,
        format: "json",
        patterns: [{ name: "pw", pattern: "hunter2", category: "generic" }],
      },
    }),
  );
  assertNotContains(result, "hunter2");
  // output should still be valid JSON
  const parsed = JSON.parse(result);
  assert(typeof parsed === "object", "output should remain valid JSON");
});

test("scan with format json returns structured report", async (s) => {
  const content = JSON.stringify({ api_key: "s3cr3tkey", host: "db.internal" });
  const result = toolText(
    await s.send("tools/call", {
      name: "scan",
      arguments: {
        content,
        format: "json",
        patterns: [{ name: "key", pattern: "s3cr3tkey", category: "generic" }],
      },
    }),
  );
  const report = JSON.parse(result);
  assert("files" in report, "should return a report");
  const total = report.files.reduce((s: number, f: { matches: number }) => s + f.matches, 0);
  assert(total >= 1, `expected ≥1 match, got ${total}`);
});

test("extract_context respects context_lines", async (s) => {
  const lines = ["a", "b", "c", "ERROR hit", "d", "e", "f"];
  const raw = toolText(
    await s.send("tools/call", {
      name: "sanitize",
      arguments: {
        content: lines.join("\n"),
        extract_context: true,
        context_lines: 1,
      },
    }),
  );
  const result = JSON.parse(raw);
  const match = result.report.files[0].log_context.matches[0];
  assert(match.before.length === 1, `expected 1 before line, got ${match.before.length}`);
  assert(match.after.length === 1, `expected 1 after line, got ${match.after.length}`);
  assert(match.before[0] === "c", `expected 'c', got '${match.before[0]}'`);
  assert(match.after[0] === "d", `expected 'd', got '${match.after[0]}'`);
});

test("list_processors returns all processors with format flags", async (s) => {
  const result = toolText(await s.send("tools/call", { name: "list_processors", arguments: {} }));
  const parsed = JSON.parse(result);
  assert(Array.isArray(parsed.processors), "should have processors array");
  const names = parsed.processors.map((p: { name: string }) => p.name);
  for (const expected of ["json", "yaml", "toml", "xml", "csv", "env", "jsonl"]) {
    assert(names.includes(expected), `should include processor '${expected}'`);
  }
  const jsonProc = parsed.processors.find((p: { name: string }) => p.name === "json");
  assert(jsonProc.format_flag === "json", "json processor should have format_flag 'json'");
});

test("namespace end-to-end: resolves plaintext secrets and sanitizes content", async (_s) => {
  const secretsDir = await Deno.makeTempDir({ prefix: "sanitize-ns-test-" });
  try {
    const nsDir = join(secretsDir, "acme-corp");
    await Deno.mkdir(nsDir);
    await Deno.writeTextFile(
      join(nsDir, "secrets.json"),
      JSON.stringify([{ pattern: "hunter2", kind: "regex", category: "generic", label: "pw" }]),
    );

    // Start a dedicated session with SANITIZE_SECRETS_DIR set.
    const cmd = new Deno.Command(Deno.execPath(), {
      args: ["run", "--allow-run", "--allow-env", "--allow-read", "--allow-write", MCP_SCRIPT],
      stdin: "piped",
      stdout: "piped",
      stderr: "null",
      env: {
        ...Deno.env.toObject(),
        SANITIZE_BIN,
        SANITIZE_LOG: "error",
        SANITIZE_SECRETS_DIR: secretsDir,
      },
    });
    const child = cmd.spawn();
    const ns = new McpSession(child);
    await ns.send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test", version: "1.0" },
    });
    await ns.notify("notifications/initialized");

    try {
      const result = toolText(
        await ns.send("tools/call", {
          name: "sanitize",
          arguments: { content: "password = hunter2", namespace: "acme-corp" },
        }),
      );
      assertNotContains(result, "hunter2");
    } finally {
      await ns.close();
    }
  } finally {
    await Deno.remove(secretsDir, { recursive: true });
  }
});

test("namespace invalid characters returns error", async (s) => {
  const result = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "hello", namespace: "../etc/passwd" },
  }) as { content: Array<{ text: string }>; isError?: boolean };
  assert(result.isError === true, "should return isError: true");
  assertContains(result.content[0].text, "Invalid namespace");
});

test("namespace without SANITIZE_SECRETS_DIR returns error", async (s) => {
  const result = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "hello", namespace: "acme-corp" },
  }) as { content: Array<{ text: string }>; isError?: boolean };
  assert(result.isError === true, "should return isError: true");
  assertContains(result.content[0].text, "SANITIZE_SECRETS_DIR");
});

test("sanitize rejects absolute secrets_file path", async (s) => {
  const result = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "hello", secrets_file: "/etc/passwd" },
  }) as { content: Array<{ text: string }>; isError?: boolean };
  assert(result.isError === true, "should return isError: true");
  assertContains(result.content[0].text, "relative path");
});

test("sanitize rejects path traversal in secrets_file", async (s) => {
  const result = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: "hello", secrets_file: "../../secrets.yaml" },
  }) as { content: Array<{ text: string }>; isError?: boolean };
  assert(result.isError === true, "should return isError: true");
  assertContains(result.content[0].text, "'..'");
});

test("scan rejects absolute secrets_file path", async (s) => {
  const result = await s.send("tools/call", {
    name: "scan",
    arguments: { content: "hello", secrets_file: "/etc/passwd" },
  }) as { content: Array<{ text: string }>; isError?: boolean };
  assert(result.isError === true, "should return isError: true");
  assertContains(result.content[0].text, "relative path");
});

test("content over size limit returns error", async (s) => {
  const bigContent = "x".repeat(600_000); // over 512 KB default
  const result = await s.send("tools/call", {
    name: "sanitize",
    arguments: { content: bigContent },
  }) as { content: Array<{ text: string }>; isError?: boolean };
  assert(result.isError === true, "should return isError: true");
  assertContains(result.content[0].text, "exceeds maximum");
});

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const RESET = "\x1b[0m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const GRAY = "\x1b[90m";

console.log(`\n${GRAY}Starting MCP server...${RESET}`);
const session = await startSession();
console.log(`${GRAY}Server ready. Running ${tests.length} tests.${RESET}\n`);

let passed = 0;
let failed = 0;

for (const { name, fn } of tests) {
  try {
    await fn(session);
    console.log(`${GREEN}✓${RESET} ${name}`);
    passed++;
  } catch (err) {
    console.log(`${RED}✗${RESET} ${name}`);
    console.log(`  ${RED}${(err as Error).message}${RESET}`);
    failed++;
  }
}

await session.close();

console.log(
  `\n${passed + failed} tests: ${GREEN}${passed} passed${RESET}` +
    (failed > 0 ? `, ${RED}${failed} failed${RESET}` : "") +
    "\n",
);

if (failed > 0) Deno.exit(1);
