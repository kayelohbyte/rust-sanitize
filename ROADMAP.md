# Roadmap

> Status: **0.17.0** — pre-1.0, API stabilizing. This document is a guide to
> intent, not a commitment; priorities shift with feedback.

## Where things stand

`scour-secrets` is feature-complete for its core job: detecting and one-way
sanitizing structured secrets in logs, configs, and archives, as a CLI, a Rust
library, and an MCP server. The library API and the encrypted secrets-file
format are considered stable as of 0.16.0 (the format carries a version byte so
it can evolve without silent breakage).

**The CLI surface is deliberately *not* frozen yet.** With ~120 flags and
several output schemas (report JSON, SARIF, NDJSON findings, exit codes), we
want real-world usage to inform what stays, merges, or changes before we commit
to it for 1.0. If a flag or output shape is awkward for you, now is the time to
say so — see [Feedback](#feedback).

## Toward 1.0

These are the gates between here and a 1.0 that we're comfortable freezing:

- **CLI stability audit + written policy.** Review every flag, the report/SARIF/
  findings schemas, and exit codes; deprecate or merge what's awkward; then
  publish a stability contract describing what SemVer means for each. Held open
  pending feedback (see above).
- **Mechanical API-compatibility enforcement.** CI runs `cargo-semver-checks`
  against the published baseline so accidental breaking changes to the library
  API fail a PR. (Active once the crate is published to crates.io.)
- **Internal decomposition.** Break up the largest modules (the streaming
  scanner and archive processor) for readability and easier contribution —
  internal-only, no API impact.

There is no fixed date. 1.0 ships when the CLI has settled under real use and
the above are done.

## Under consideration (pre-1.0 candidates)

Scoped ideas that came out of real-bundle testing; likely next-minor material
once their design questions are settled.

- **`seed: true` on scanner regex entries.** Today only *profile-discovered*
  field values are seeded into the scanner as literals; a scanner regex
  capture matches only where its keyword context appears. An opt-in `seed`
  flag would let a keyed pattern (e.g. `HOSTNAME=(...)`) discover a value once
  and scrub its bare occurrences everywhere — the same two-pass guarantee the
  profiles get, for formats no structured processor covers. Needs a discovery
  pre-pass for scanner patterns, mirroring the existing profile pre-pass.
- **Hostname replacement domain-suffix policy.** The hostname category
  preserves everything after the first dot so replacements stay plausible
  (`db01.corp.example.com` → `x9f2.corp.example.com`) — which deliberately
  leaves internal domain names visible. Decide whether that stays the default,
  becomes configurable, or splits into distinct hostname/FQDN categories, and
  document the choice.
- **Span-edit support for `command_output`.** The processor currently
  implements only `process` (re-serialization); implementing
  `process_to_edits` would give it the byte-exact span-editing fast path the
  other structured editors use inside archives.

## Deliberately deferred (post-1.0)

These are understood and scoped but intentionally **not** planned for 1.0. Their
absence is a choice, not an oversight — the common single-user, single-agent
workflow does not need them, and several add meaningful surface area (concurrency
bounds, packaging channels) that we'd rather not commit to prematurely.

- **Multi-session / multi-tenant HTTP daemon.** The `--http` MCP daemon is
  single-session today. Concurrent multi-agent support needs per-session
  protocol plumbing plus careful subprocess-concurrency bounds; deferred until
  there's demand for shared-daemon use.
- **Per-tenant deterministic replacement.** Isolated, per-namespace deterministic
  seeds for multi-tenant setups (the single-tenant primitives —
  `--deterministic` + `--seed-salt-file` — already exist).
- **Version-update notifications.** Telling users when a newer release exists.
- **Socket activation.** systemd/launchd socket-activated daemon startup.
- **Packaging channels.** `winget` (and potentially other OS package managers)
  beyond the current crates.io + release-binary distribution.
- **Community app-bundle registry.** A discoverable, shareable registry of
  user-authored app bundles beyond the 28 built-ins.

## Feedback

Pre-1.0 is exactly when feedback is most useful. Open an issue for bugs, missing
detections, awkward flags, or output-schema friction. For security-sensitive
reports, use a private security advisory rather than a public issue (see
[SECURITY.md](SECURITY.md)).
