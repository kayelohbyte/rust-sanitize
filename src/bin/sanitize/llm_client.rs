use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

/// Maximum bytes accepted from the SSE response stream.
const MAX_STREAM_BYTES: usize = 10 * 1024 * 1024; // 10 MB

/// Maximum bytes read from an HTTP error body.
const MAX_ERROR_BODY_BYTES: u64 = 4 * 1024; // 4 KB

/// Validate that `endpoint` uses an http or https scheme.
/// Called from `validate_args` before the HTTP request is made.
pub(crate) fn validate_endpoint_scheme(endpoint: &str) -> Result<(), String> {
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Err(format!(
            "--llm-endpoint must start with http:// or https://; got: {endpoint}"
        ));
    }
    Ok(())
}

/// POST a prompt to an OpenAI-compatible `/v1/chat/completions` endpoint
/// and stream the response to stdout.
///
/// `key` may be any non-empty string for local models (Ollama, LM Studio).
/// The endpoint must support streaming (`stream: true`).
pub(crate) fn send_prompt(
    endpoint: &str,
    model: &str,
    key: &str,
    prompt: &str,
) -> Result<(), String> {
    let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));

    let body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": true
    });

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(300))
        .build();

    let response = agent
        .post(&url)
        .set("Authorization", &format!("Bearer {key}"))
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let mut buf = Vec::new();
                let _ = resp.into_reader().take(MAX_ERROR_BODY_BYTES).read_to_end(&mut buf);
                let body = String::from_utf8_lossy(&buf);
                format!("LLM endpoint returned HTTP {code}: {body}")
            }
            ureq::Error::Transport(t) => {
                format!("failed to reach LLM endpoint: {t}")
            }
        })?;

    let reader = BufReader::new(response.into_reader());
    let stdout = std::io::stdout();
    let mut total_bytes: usize = 0;

    for line in reader.lines() {
        let line = line.map_err(|e| format!("error reading LLM response stream: {e}"))?;
        // Count raw line bytes before parsing to bound memory usage for
        // malformed/adversarial responses that have no content field.
        total_bytes += line.len();
        if total_bytes > MAX_STREAM_BYTES {
            return Err(format!(
                "LLM response exceeded {} MB limit; aborting",
                MAX_STREAM_BYTES / 1024 / 1024
            ));
        }
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        if data.trim() == "[DONE]" {
            break;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(content) = val["choices"][0]["delta"]["content"].as_str() {
                // Strip ESC to prevent terminal control-sequence injection.
                let safe = content.replace('\x1b', "");
                let mut out = stdout.lock();
                out.write_all(safe.as_bytes())
                    .map_err(|e| format!("failed to write LLM response: {e}"))?;
                out.flush()
                    .map_err(|e| format!("failed to flush stdout: {e}"))?;
            }
        }
    }

    println!();
    Ok(())
}
