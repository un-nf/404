/* STATIC Proxy (AGPL-3.0)

Copyright (C) 2025 - 404 Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use http::header::{HeaderName, HeaderValue, CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY};
use rand::{rngs::OsRng, RngCore};

use crate::proxy::flow::Flow;

/// Domains Google reCAPTCHA uses for scripts (api.js + static bundles).
const CAPTCHA_SCRIPT_ALLOWLIST: &[&str] = &[
    "https://www.gstatic.com",
    "https://www.google.com",
    "https://www.recaptcha.net",
    "challenges.cloudflare.com"
];

/// Domains Google reCAPTCHA frames originate from (anchor + challenge iframes).
const CAPTCHA_FRAME_ALLOWLIST: &[&str] = &[
    "https://www.google.com",
    "https://www.recaptcha.net",
    "challenges.cloudflare.com"
];

/// Hosts whose inline script policies rely on unsafe-eval allowances (e.g., Cloudflare challenges).
const CSP_EVAL_REQUIRED_HOSTS: &[&str] = &[
    "npmjs.com",
    "npmjs.org",
    "cloudflare.com",
    "cdnjs.cloudflare.com",
    "challenges.cloudflare.com"
];

/// Hosts whose CSP should be preserved verbatim (YouTube relies on hashed slotting).
const CSP_PASSTHROUGH_HOSTS: &[&str] = &[
    "youtube.com",
    "youtube-nocookie.com",
    "ytimg.com",
    "googlevideo.com",
    "accounts.google.com",
    "drive.google.com",
    "gstatic.com",
    "recaptcha.net",
    "challenges.cloudflare.com"
];

use super::FlowStage;

/// CSP stage guarantees a nonce is present and mutates Content-Security-Policy headers so the
/// inline JS bundle always survives strict CSP deployments.
#[derive(Clone, Default)]
pub struct CspStage;

impl CspStage {
    fn rewrite_headers(&self, flow: &mut Flow, script_hashes: &[String]) -> Result<()> {
        if flow.response.is_none() {
            return Ok(());
        }

        let mut header_snapshots = if let Some(original) = flow.metadata.original_csp_headers.clone() {
            original
        } else {
            let captured = capture_csp_headers(flow);
            if !captured.is_empty() {
                flow.metadata.original_csp_headers = Some(captured.clone());
            }
            captured
        };

        if header_snapshots.is_empty() {
            header_snapshots = capture_csp_headers(flow);
        }

        if should_passthrough_csp(flow) {
            capture_nonce_from_snapshots(flow, &header_snapshots);
            return Ok(());
        }

        for (header, values) in header_snapshots {
            if let Some(response) = flow.response.as_mut() {
                response.headers.remove(header.clone());
            }

            for value in values {
                let rewritten = rewrite_csp_value(flow, &value, script_hashes);
                let enforced = enforce_eval_on_value(flow, &rewritten);
                let header_value = HeaderValue::from_str(&enforced)
                    .with_context(|| format!("invalid CSP header after rewrite: {rewritten}"))?;

                if let Some(response) = flow.response.as_mut() {
                    response.headers.append(header.clone(), header_value);
                }
            }
        }

        let needs_fallback = flow
            .response
            .as_ref()
            .map(|resp| resp.headers.get(CONTENT_SECURITY_POLICY).is_none())
            .unwrap_or(false);

        if needs_fallback {
            flow.metadata.csp_nonce = None;
            let fallback = build_fallback_policy();
            let enforced = enforce_eval_on_value(flow, &fallback);
            if let Some(response) = flow.response.as_mut() {
                response.headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_str(&enforced)?);
            }
            if flow.metadata.original_csp_headers.is_none() {
                flow.metadata.original_csp_headers = Some(vec![
                    (CONTENT_SECURITY_POLICY.clone(), vec![enforced.clone()]),
                ]);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl FlowStage for CspStage {
    /// Ensures a CSP nonce exists so injected scripts can be allowed by the browser.
    async fn on_response_headers(&self, flow: &mut Flow) -> Result<()> {
        self.rewrite_headers(flow, &[])
    }

    async fn on_response_finalized(&self, flow: &mut Flow) -> Result<()> {
        if flow.metadata.script_hashes.is_empty() {
            return Ok(());
        }

        let hashes = flow.metadata.script_hashes.clone();
        self.rewrite_headers(flow, hashes.as_slice())
    }
}

/// Generates a 128-bit random nonce encoded in base64 (no padding) for CSP headers.
fn generate_nonce() -> String {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    STANDARD_NO_PAD.encode(buf)
}

fn rewrite_csp_value(flow: &mut Flow, original: &str, script_hashes: &[String]) -> String {
    let policies: Vec<&str> = original.split(',').collect();
    let mut rewritten = Vec::with_capacity(policies.len());

    for policy in policies {
        let trimmed = policy.trim();
        if trimmed.is_empty() {
            continue;
        }
        rewritten.push(modify_policy(flow, trimmed, script_hashes));
    }

    rewritten.join(", ")
}

fn modify_policy(flow: &mut Flow, policy: &str, script_hashes: &[String]) -> String {
    let mut directives = Vec::new();
    let mut script_seen = false;
    let mut frame_seen = false;
    let mut child_seen = false;

    for directive in policy.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        if is_script_directive(directive) {
            script_seen = true;
            directives.push(build_script_directive(flow, directive, script_hashes));
        } else if is_frame_directive(directive) {
            frame_seen = true;
            directives.push(build_destination_directive(directive, "frame-src", CAPTCHA_FRAME_ALLOWLIST));
        } else if is_child_directive(directive) {
            child_seen = true;
            directives.push(build_destination_directive(directive, "child-src", CAPTCHA_FRAME_ALLOWLIST));
        } else {
            directives.push(directive.to_string());
        }
    }

    if !script_seen {
        directives.push(build_script_directive(flow, "script-src", script_hashes));
    }

    if !frame_seen && !child_seen {
        directives.push(build_destination_directive("frame-src", "frame-src", CAPTCHA_FRAME_ALLOWLIST));
    }

    directives.join("; ")
}

fn is_script_directive(input: &str) -> bool {
    let name = input
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    name == "script-src" || name == "script-src-elem"
}

fn is_frame_directive(input: &str) -> bool {
    directive_name(input) == "frame-src"
}

fn is_child_directive(input: &str) -> bool {
    directive_name(input) == "child-src"
}

fn directive_name(input: &str) -> String {
    input
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn build_script_directive(flow: &mut Flow, base: &str, script_hashes: &[String]) -> String {
    let mut parts = base.split_whitespace();
    let name = parts.next().unwrap_or("script-src");
    let mut tokens: Vec<String> = parts.map(|token| token.to_string()).collect();

    let mut has_nonce = false;
    let mut has_hash = false;
    let mut has_unsafe_inline = false;
    let mut saw_unsafe_eval = false;
    let mut saw_wasm_unsafe_eval = false;
    let mut existing_nonce: Option<String> = None;

    for token in &tokens {
        let trimmed = token.trim_matches('\'');
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.len() >= 6 && trimmed[..6].eq_ignore_ascii_case("nonce-") {
            has_nonce = true;
            if existing_nonce.is_none() {
                let value = trimmed[6..].to_string();
                existing_nonce = Some(value);
            }
        } else if lower.starts_with("sha256-") || lower.starts_with("sha384-") || lower.starts_with("sha512-") {
            has_hash = true;
        } else if lower == "unsafe-inline" {
            has_unsafe_inline = true;
        } else if lower == "unsafe-eval" {
            saw_unsafe_eval = true;
        } else if lower == "wasm-unsafe-eval" {
            saw_wasm_unsafe_eval = true;
        }
    }

    if let Some(value) = existing_nonce.clone() {
        if flow.metadata.csp_nonce.is_none() {
            flow.metadata.csp_nonce = Some(value);
        }
    }

    if !has_nonce && !has_unsafe_inline {
        let nonce_value = flow
            .metadata
            .csp_nonce
            .clone()
            .unwrap_or_else(|| {
                let fresh = generate_nonce();
                flow.metadata.csp_nonce = Some(fresh.clone());
                fresh
            });
        tokens.push(format!("'nonce-{}'", nonce_value));
        has_nonce = true;
    }

    let allow_hashes = !has_unsafe_inline || has_nonce || has_hash;

    if allow_hashes {
        for hash in script_hashes {
            let hash_token = format!("'sha256-{}'", hash);
            if !tokens.iter().any(|token| token == &hash_token) {
                tokens.push(hash_token);
            }
        }
    }

    append_allowlist_tokens(&mut tokens, CAPTCHA_SCRIPT_ALLOWLIST);

    ensure_eval_tokens(
        flow,
        &mut tokens,
        saw_unsafe_eval,
        saw_wasm_unsafe_eval,
    );

    if tokens.is_empty() {
        tokens.push("'self'".to_string());
    }

    format!("{} {}", name, tokens.join(" "))
}

fn build_destination_directive(base: &str, default_name: &str, allowlist: &[&str]) -> String {
    let mut parts = base.split_whitespace();
    let name = parts.next().unwrap_or(default_name);
    let mut tokens: Vec<String> = parts.map(|token| token.to_string()).collect();

    if tokens.is_empty() {
        tokens.push("'self'".to_string());
    }

    append_allowlist_tokens(&mut tokens, allowlist);

    format!("{} {}", name, tokens.join(" "))
}

fn append_allowlist_tokens(tokens: &mut Vec<String>, allowlist: &[&str]) {
    for origin in allowlist {
        if !tokens.iter().any(|token| token == origin) {
            tokens.push((*origin).to_string());
        }
    }
}

fn ensure_eval_tokens(
    flow: &Flow,
    tokens: &mut Vec<String>,
    saw_unsafe_eval: bool,
    saw_wasm_unsafe_eval: bool,
) {
    let host_needs_eval = host_requires_eval(flow);

    if saw_unsafe_eval || host_needs_eval {
        append_unique_token(tokens, "'unsafe-eval'");
    }

    if saw_wasm_unsafe_eval || host_needs_eval {
        append_unique_token(tokens, "'wasm-unsafe-eval'");
    }
}

fn append_unique_token(tokens: &mut Vec<String>, token: &str) {
    if !tokens.iter().any(|existing| existing.eq_ignore_ascii_case(token)) {
        tokens.push(token.to_string());
    }
}

fn enforce_eval_on_value(flow: &Flow, value: &str) -> String {
    if !host_requires_eval(flow) {
        return value.to_string();
    }

    let mut directives = Vec::new();
    let mut script_seen = false;

    for directive in value.split(';') {
        let trimmed = directive.trim();
        if trimmed.is_empty() {
            continue;
        }

        if is_script_directive(trimmed) {
            script_seen = true;
            directives.push(add_eval_tokens_to_directive(trimmed));
        } else {
            directives.push(trimmed.to_string());
        }
    }

    if !script_seen {
        directives.push("script-src 'unsafe-eval' 'wasm-unsafe-eval'".to_string());
    }

    directives.join("; ")
}

fn add_eval_tokens_to_directive(directive: &str) -> String {
    let mut parts = directive.split_whitespace();
    let name = parts.next().unwrap_or("script-src");
    let mut tokens: Vec<String> = parts.map(|token| token.to_string()).collect();
    append_unique_token(&mut tokens, "'unsafe-eval'");
    append_unique_token(&mut tokens, "'wasm-unsafe-eval'");
    format!("{} {}", name, tokens.join(" "))
}

fn build_fallback_policy() -> String {
    let mut script_tokens = vec!["'self'".to_string(), "'unsafe-inline'".to_string()];
    append_allowlist_tokens(&mut script_tokens, CAPTCHA_SCRIPT_ALLOWLIST);

    let mut frame_tokens = vec!["'self'".to_string()];
    append_allowlist_tokens(&mut frame_tokens, CAPTCHA_FRAME_ALLOWLIST);
    let frame_value = frame_tokens.join(" ");

    format!(
        "script-src {}; frame-src {}; child-src {}; object-src 'none'; base-uri 'none'",
        script_tokens.join(" "),
        frame_value,
        frame_value
    )
}

fn capture_nonce_from_snapshots(flow: &mut Flow, snapshots: &[(HeaderName, Vec<String>)]) {
    if flow.metadata.csp_nonce.is_some() {
        return;
    }
    for (_, values) in snapshots {
        for value in values {
            if let Some(nonce) = extract_nonce_from_value(value) {
                flow.metadata.csp_nonce = Some(nonce);
                return;
            }
        }
    }
}

fn extract_nonce_from_value(value: &str) -> Option<String> {
    for directive in value.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }
        if !is_script_directive(directive) {
            continue;
        }
        let mut parts = directive.split_whitespace();
        let _ = parts.next();
        for token in parts {
            let trimmed = token.trim_matches('\'');
            if trimmed.len() >= 6 && trimmed[..6].eq_ignore_ascii_case("nonce-") {
                return Some(trimmed[6..].to_string());
            }
        }
    }
    None
}

fn should_passthrough_csp(flow: &Flow) -> bool {
    match request_host(flow) {
        Some(host) => CSP_PASSTHROUGH_HOSTS
            .iter()
            .any(|suffix| host_matches_suffix(&host, suffix)),
        None => false,
    }
}

fn host_requires_eval(flow: &Flow) -> bool {
    match request_host(flow) {
        Some(host) => CSP_EVAL_REQUIRED_HOSTS
            .iter()
            .any(|suffix| host_matches_suffix(&host, suffix)),
        None => false,
    }
}

fn request_host(flow: &Flow) -> Option<String> {
    if let Some(host) = flow.request.uri.host() {
        return Some(host.to_ascii_lowercase());
    }
    if let Some(sni) = &flow.metadata.tls_sni {
        return Some(sni.to_ascii_lowercase());
    }
    if let Some(target) = &flow.metadata.connect_target {
        if let Some((host, _)) = target.split_once(':') {
            return Some(host.to_ascii_lowercase());
        }
        return Some(target.to_ascii_lowercase());
    }
    None
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    if host.len() <= suffix.len() {
        return false;
    }
    host.ends_with(suffix)
        && host
            .as_bytes()
            .get(host.len() - suffix.len() - 1)
            .map(|byte| *byte == b'.')
            .unwrap_or(false)
}

fn capture_csp_headers(flow: &Flow) -> Vec<(HeaderName, Vec<String>)> {
    let mut snapshots = Vec::new();
    let response = match flow.response.as_ref() {
        Some(resp) => resp,
        None => return snapshots,
    };

    for header in [CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY].iter() {
        let values: Vec<String> = response
            .headers
            .get_all(header)
            .iter()
            .filter_map(|value| value.to_str().ok().map(|s| s.to_string()))
            .collect();

        if !values.is_empty() {
            snapshots.push((header.clone(), values));
        }
    }

    snapshots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::{Flow, RequestParts, ResponseParts};

    #[test]
    fn script_directive_includes_captcha_hosts() {
        let mut flow = Flow::new(RequestParts::default());
        let directive = build_script_directive(&mut flow, "script-src 'self'", &[]);
        assert!(directive.contains("https://www.gstatic.com"));
        assert!(directive.contains("https://www.google.com"));
    }

    #[test]
    fn adds_frame_directive_when_missing() {
        let mut flow = Flow::new(RequestParts::default());
        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("script-src 'self'"),
        );
        flow.response = Some(response);

        let stage = CspStage;
        stage.rewrite_headers(&mut flow, &[]).unwrap();
        let header_value = flow
            .response
            .as_ref()
            .unwrap()
            .headers
            .get(CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        assert!(header_value.contains("frame-src"));
        assert!(header_value.contains("https://www.google.com"));
    }

    #[test]
    fn fallback_policy_whitelists_captcha() {
        let fallback = build_fallback_policy();
        assert!(fallback.contains("https://www.gstatic.com"));
        assert!(fallback.contains("frame-src"));
    }
}
