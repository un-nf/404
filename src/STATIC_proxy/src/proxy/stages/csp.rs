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
use http::header::{HeaderName, HeaderValue, CONTENT_SECURITY_POLICY};
use rand::{rngs::OsRng, RngCore};

use crate::proxy::flow::Flow;

use super::FlowStage;

/// CSP stage preserves origin CSP and only adds or reuses a nonce on the relevant
/// script directive so the injected runtime can execute.
#[derive(Clone, Default)]
pub struct CspStage;

impl CspStage {
    fn rewrite_headers(&self, flow: &mut Flow, _script_hashes: &[String]) -> Result<()> {
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

        capture_nonce_from_snapshots(flow, &header_snapshots);

        if header_snapshots.is_empty() {
            return Ok(());
        }

        for (header, values) in header_snapshots {
            if let Some(response) = flow.response.as_mut() {
                response.headers.remove(header.clone());
            }

            for value in values {
                let rewritten = rewrite_csp_value(flow, &value);
                let header_value = HeaderValue::from_str(&rewritten)
                    .with_context(|| format!("invalid CSP header after rewrite: {rewritten}"))?;

                if let Some(response) = flow.response.as_mut() {
                    response.headers.append(header.clone(), header_value);
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl FlowStage for CspStage {
    /// Reuses or adds a CSP nonce on script directives without otherwise rewriting policy.
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

fn rewrite_csp_value(flow: &mut Flow, original: &str) -> String {
    let policies: Vec<&str> = original.split(',').collect();
    let mut rewritten = Vec::with_capacity(policies.len());

    for policy in policies {
        let trimmed = policy.trim();
        if trimmed.is_empty() {
            continue;
        }
        rewritten.push(modify_policy(flow, trimmed));
    }

    rewritten.join(", ")
}

fn modify_policy(flow: &mut Flow, policy: &str) -> String {
    let mut directives = Vec::new();
    let mut script_elem_index = None;
    let mut script_index = None;
    let mut default_src = None;

    for directive in policy.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        let name = directive_name(directive);
        if name == "script-src-elem" {
            script_elem_index = Some(directives.len());
            directives.push(directive.to_string());
        } else if name == "script-src" {
            script_index = Some(directives.len());
            directives.push(directive.to_string());
        } else if name == "default-src" {
            default_src = Some(directive.to_string());
            directives.push(directive.to_string());
        } else {
            directives.push(directive.to_string());
        }
    }

    if let Some(index) = script_elem_index {
        directives[index] = ensure_nonce_on_directive(flow, &directives[index], "script-src-elem");
    } else if let Some(index) = script_index {
        directives.push(build_derived_script_elem_directive(flow, &directives[index], "script-src-elem"));
    } else if let Some(default_src) = default_src {
        directives.push(build_derived_script_elem_directive(flow, &default_src, "script-src-elem"));
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

fn directive_name(input: &str) -> String {
    input
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn ensure_nonce_on_directive(flow: &mut Flow, base: &str, fallback_name: &str) -> String {
    let mut parts = base.split_whitespace();
    let name = parts.next().unwrap_or(fallback_name);
    let mut tokens: Vec<String> = parts.map(|token| token.to_string()).collect();

    let mut has_nonce = false;
    let mut existing_nonce: Option<String> = None;

    for token in &tokens {
        let trimmed = token.trim_matches('\'');
        if trimmed.len() >= 6 && trimmed[..6].eq_ignore_ascii_case("nonce-") {
            has_nonce = true;
            if existing_nonce.is_none() {
                let value = trimmed[6..].to_string();
                existing_nonce = Some(value);
            }
        }
    }

    if let Some(value) = existing_nonce.clone() {
        if flow.metadata.csp_nonce.is_none() {
            flow.metadata.csp_nonce = Some(value);
        }
    }

    if !has_nonce {
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
    }

    format!("{} {}", name, tokens.join(" "))
}

fn build_derived_script_elem_directive(flow: &mut Flow, source_directive: &str, target_name: &str) -> String {
    let mut parts = source_directive.split_whitespace();
    let _ = parts.next();
    let tokens: Vec<String> = parts.map(|token| token.to_string()).collect();
    ensure_nonce_on_directive(
        flow,
        &format!("{} {}", target_name, tokens.join(" ")).trim_end().to_string(),
        target_name,
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

fn capture_csp_headers(flow: &Flow) -> Vec<(HeaderName, Vec<String>)> {
    let mut snapshots = Vec::new();
    let response = match flow.response.as_ref() {
        Some(resp) => resp,
        None => return snapshots,
    };

    let values: Vec<String> = response
        .headers
        .get_all(CONTENT_SECURITY_POLICY)
        .iter()
        .filter_map(|value| value.to_str().ok().map(|s| s.to_string()))
        .collect();

    if !values.is_empty() {
        snapshots.push((CONTENT_SECURITY_POLICY, values));
    }

    snapshots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::{Flow, RequestParts, ResponseParts};
    use http::header::CONTENT_SECURITY_POLICY_REPORT_ONLY;

    #[test]
    fn script_src_elem_preserves_existing_policy_and_adds_nonce() {
        let mut flow = Flow::new(RequestParts::default());
        let rewritten = rewrite_csp_value(
            &mut flow,
            "default-src 'self'; script-src-elem 'self' https://cdn.example; object-src 'none'",
        );

        assert!(rewritten.contains("default-src 'self'"));
        assert!(rewritten.contains("script-src-elem 'self' https://cdn.example 'nonce-"));
        assert!(rewritten.contains("object-src 'none'"));
    }

    #[test]
    fn script_src_gets_nonce_when_script_src_elem_is_absent() {
        let mut flow = Flow::new(RequestParts::default());
        let rewritten = rewrite_csp_value(&mut flow, "script-src 'self' https://cdn.example");

        assert_eq!(
            rewritten,
            format!(
                "script-src 'self' https://cdn.example; script-src-elem 'self' https://cdn.example 'nonce-{}'",
                flow.metadata.csp_nonce.clone().unwrap()
            )
        );
    }

    #[test]
    fn default_src_is_copied_into_script_src_elem_when_needed() {
        let mut flow = Flow::new(RequestParts::default());
        let rewritten = rewrite_csp_value(&mut flow, "default-src 'self' https://cdn.example; object-src 'none'");

        assert!(rewritten.contains("default-src 'self' https://cdn.example"));
        assert!(rewritten.contains("script-src-elem 'self' https://cdn.example 'nonce-"));
        assert!(rewritten.contains("object-src 'none'"));
    }

    #[test]
    fn existing_nonce_is_reused() {
        let mut flow = Flow::new(RequestParts::default());
        let rewritten = rewrite_csp_value(&mut flow, "script-src-elem 'self' 'nonce-origin123' https://cdn.example");

        assert_eq!(rewritten, "script-src-elem 'self' 'nonce-origin123' https://cdn.example");
        assert_eq!(flow.metadata.csp_nonce.as_deref(), Some("origin123"));
    }

    #[test]
    fn script_src_unsafe_inline_is_preserved_for_attributes() {
        let mut flow = Flow::new(RequestParts::default());
        let rewritten = rewrite_csp_value(
            &mut flow,
            "script-src blob: https://duckduckgo.com 'unsafe-inline' 'unsafe-eval' 'nonce-origin123'",
        );

        assert_eq!(
            rewritten,
            "script-src blob: https://duckduckgo.com 'unsafe-inline' 'unsafe-eval' 'nonce-origin123'; script-src-elem blob: https://duckduckgo.com 'unsafe-inline' 'unsafe-eval' 'nonce-origin123'"
        );
        assert_eq!(flow.metadata.csp_nonce.as_deref(), Some("origin123"));
    }

    #[test]
    fn script_src_nonce_does_not_gain_additional_nonce_token() {
        let mut flow = Flow::new(RequestParts::default());
        let rewritten = rewrite_csp_value(&mut flow, "script-src 'self' 'nonce-origin123'");

        assert_eq!(
            rewritten,
            "script-src 'self' 'nonce-origin123'; script-src-elem 'self' 'nonce-origin123'"
        );
        assert_eq!(flow.metadata.csp_nonce.as_deref(), Some("origin123"));
    }

    #[test]
    fn rewrite_headers_leaves_responses_without_csp_untouched() {
        let mut flow = Flow::new(RequestParts::default());
        flow.response = Some(ResponseParts::default());

        let stage = CspStage;
        stage.rewrite_headers(&mut flow, &[]).unwrap();

        assert!(flow.response.as_ref().unwrap().headers.get(CONTENT_SECURITY_POLICY).is_none());
    }

    #[test]
    fn rewrite_headers_leaves_report_only_policy_untouched() {
        let mut flow = Flow::new(RequestParts::default());
        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY_REPORT_ONLY,
            HeaderValue::from_static("script-src 'self'; connect-src 'none'"),
        );
        flow.response = Some(response);

        let stage = CspStage;
        stage.rewrite_headers(&mut flow, &[]).unwrap();

        assert_eq!(
            flow.response
                .as_ref()
                .unwrap()
                .headers
                .get(CONTENT_SECURITY_POLICY_REPORT_ONLY)
                .unwrap(),
            &HeaderValue::from_static("script-src 'self'; connect-src 'none'")
        );
        assert!(flow.metadata.csp_nonce.is_none());
    }
}
