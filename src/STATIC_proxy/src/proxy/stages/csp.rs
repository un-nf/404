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

use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64_STANDARD_NO_PAD;
use http::header::CONTENT_SECURITY_POLICY;
use http::HeaderValue;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::proxy::flow::{Flow, ResponseParts};

use super::FlowStage;

#[derive(Clone, Default)]
pub struct CspStage;

#[async_trait]
impl FlowStage for CspStage {
    async fn on_response_headers(&self, flow: &mut Flow) -> Result<()> {
        let response = match flow.response.as_ref() {
            Some(response) => response,
            None => return Ok(()),
        };

        let csp_values: Vec<String> = response
            .headers
            .get_all(CONTENT_SECURITY_POLICY)
            .iter()
            .filter_map(|value| value.to_str().ok().map(|raw| raw.to_string()))
            .collect();

        if csp_values.is_empty() {
            return Ok(());
        }

        if let Some(nonce) = csp_values.iter().find_map(|value| extract_existing_nonce(value)) {
            flow.metadata.csp_nonce = Some(nonce);
            return Ok(());
        }

        flow.metadata.csp_nonce = Some(generate_proxy_nonce());

        Ok(())
    }

    async fn on_response_finalized(&self, flow: &mut Flow) -> Result<()> {
        if !flow.metadata.script_injected {
            return Ok(());
        }

        let Some(nonce) = flow.metadata.csp_nonce.as_deref() else {
            return Ok(());
        };

        let Some(response) = flow.response.as_mut() else {
            return Ok(());
        };

        rewrite_csp_headers_for_injected_nonce(response, nonce)?;
        Ok(())
    }
}

pub(crate) fn generate_proxy_nonce() -> String {
    let mut nonce_bytes = [0u8; 18];
    OsRng.fill_bytes(&mut nonce_bytes);
    BASE64_STANDARD_NO_PAD.encode(nonce_bytes)
}

pub(crate) fn extract_existing_nonce(csp: &str) -> Option<String> {
    for directive in csp.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        let name = directive
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name != "script-src" && name != "script-src-elem" {
            continue;
        }

        for token in directive.split_whitespace().skip(1) {
            let trimmed = token.trim_matches('\'');
            if trimmed.len() > 6 && trimmed[..6].eq_ignore_ascii_case("nonce-") {
                return Some(trimmed[6..].to_string());
            }
        }
    }

    None
}

fn rewrite_csp_headers_for_injected_nonce(response: &mut ResponseParts, nonce: &str) -> Result<()> {
    let values = response
        .headers
        .get_all(CONTENT_SECURITY_POLICY)
        .iter()
        .filter_map(|value| value.to_str().ok().map(|raw| raw.to_string()))
        .collect::<Vec<_>>();

    if values.is_empty() {
        return Ok(());
    }

    response.headers.remove(CONTENT_SECURITY_POLICY);
    for value in values {
        let rewritten = rewrite_policy_for_injected_nonce(&value, nonce);
        let header = HeaderValue::from_str(&rewritten)?;
        response.headers.append(CONTENT_SECURITY_POLICY, header);
    }

    Ok(())
}

pub(crate) fn rewrite_policy_for_injected_nonce(csp: &str, nonce: &str) -> String {
    let nonce_token = format!("'nonce-{nonce}'");
    let mut rewritten = Vec::new();
    let mut default_tokens: Option<Vec<String>> = None;
    let mut child_tokens: Option<Vec<String>> = None;
    let mut script_tokens: Option<Vec<String>> = None;
    let mut saw_script_src = false;
    let mut saw_worker_src = false;

    for directive in csp.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        let mut tokens = directive
            .split_whitespace()
            .map(|token| token.to_string())
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }

        let name = tokens[0].to_ascii_lowercase();
        match name.as_str() {
            "default-src" => {
                default_tokens = Some(tokens[1..].to_vec());
                rewritten.push(directive.to_string());
            }
            "child-src" => {
                child_tokens = Some(tokens[1..].to_vec());
                rewritten.push(directive.to_string());
            }
            "script-src" => {
                saw_script_src = true;
                append_csp_token_if_missing(&mut tokens, &nonce_token);
                script_tokens = Some(tokens[1..].to_vec());
                rewritten.push(tokens.join(" "));
            }
            "script-src-elem" => {
                append_csp_token_if_missing(&mut tokens, &nonce_token);
                rewritten.push(tokens.join(" "));
            }
            "worker-src" => {
                saw_worker_src = true;
                append_csp_token_if_missing(&mut tokens, "blob:");
                rewritten.push(tokens.join(" "));
            }
            _ => rewritten.push(directive.to_string()),
        }
    }

    if !saw_script_src {
        if let Some(default_tokens) = default_tokens.as_ref() {
            let mut tokens = vec!["script-src".to_string()];
            tokens.extend(default_tokens.clone());
            append_csp_token_if_missing(&mut tokens, &nonce_token);
            script_tokens = Some(tokens[1..].to_vec());
            rewritten.push(tokens.join(" "));
        }
    }

    if !saw_worker_src {
        let inherited_tokens = child_tokens
            .as_deref()
            .or(script_tokens.as_deref())
            .or(default_tokens.as_deref())
            .map(filter_worker_source_tokens)
            .unwrap_or_else(|| vec!["'self'".to_string()]);

        let mut tokens = vec!["worker-src".to_string()];
        tokens.extend(inherited_tokens);
        append_csp_token_if_missing(&mut tokens, "blob:");
        rewritten.push(tokens.join(" "));
    }

    rewritten.join("; ")
}

fn append_csp_token_if_missing(tokens: &mut Vec<String>, expected: &str) {
    if !is_none_token(expected) {
        tokens.retain(|token| !is_none_token(token));
    }

    if tokens.iter().skip(1).any(|token| token.eq_ignore_ascii_case(expected)) {
        return;
    }

    tokens.push(expected.to_string());
}

fn filter_worker_source_tokens(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|token| should_retain_worker_source_token(token))
        .cloned()
        .collect()
}

fn should_retain_worker_source_token(token: &str) -> bool {
    let normalized = token.trim().trim_matches('"').to_ascii_lowercase();

    if normalized.is_empty() {
        return false;
    }

    if is_none_token(&normalized) {
        return true;
    }

    if normalized.starts_with("'nonce-") || normalized.starts_with("'sha") {
        return false;
    }

    !matches!(
        normalized.as_str(),
        "'unsafe-inline'" | "'unsafe-eval'" | "'strict-dynamic'" | "'report-sample'" | "'wasm-unsafe-eval'"
    )
}

fn is_none_token(token: &str) -> bool {
    token.trim().trim_matches('"').eq_ignore_ascii_case("'none'")
        || token.trim().eq_ignore_ascii_case("none")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::{Flow, RequestParts, ResponseParts};
    use http::header::CONTENT_SECURITY_POLICY_REPORT_ONLY;

    #[test]
    fn extract_existing_nonce_reads_script_directives_only() {
        assert_eq!(
            extract_existing_nonce("default-src 'self'; script-src 'self' 'nonce-origin123' https://cdn.example"),
            Some("origin123".to_string())
        );
        assert_eq!(extract_existing_nonce("default-src 'self' 'nonce-ignoreme'"), None);
    }

    #[tokio::test]
    async fn on_response_headers_generates_nonce_without_rewriting_policy() {
        let mut flow = Flow::new(RequestParts::default());
        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("script-src 'self' 'unsafe-inline' https://cdn.example"),
        );
        flow.response = Some(response);

        let stage = CspStage;
        stage.on_response_headers(&mut flow).await.unwrap();

        assert_eq!(
            flow.response
                .as_ref()
                .unwrap()
                .headers
                .get(CONTENT_SECURITY_POLICY)
                .unwrap(),
            &HeaderValue::from_static("script-src 'self' 'unsafe-inline' https://cdn.example")
        );
        assert!(flow.metadata.csp_nonce.is_some());
    }

    #[tokio::test]
    async fn on_response_headers_reuses_origin_nonce_without_rewriting_policy() {
        let mut flow = Flow::new(RequestParts::default());
        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("script-src 'self' 'nonce-origin123' 'unsafe-inline' https://cdn.example"),
        );
        flow.response = Some(response);

        let stage = CspStage;
        stage.on_response_headers(&mut flow).await.unwrap();

        assert_eq!(
            flow.response
                .as_ref()
                .unwrap()
                .headers
                .get(CONTENT_SECURITY_POLICY)
                .unwrap(),
            &HeaderValue::from_static("script-src 'self' 'nonce-origin123' 'unsafe-inline' https://cdn.example")
        );
        assert_eq!(flow.metadata.csp_nonce.as_deref(), Some("origin123"));
    }

    #[tokio::test]
    async fn on_response_finalized_rewrites_policy_after_injection() {
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.script_injected = true;
        flow.metadata.csp_nonce = Some("fresh123".to_string());

        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("script-src 'self' 'unsafe-inline' https://cdn.example"),
        );
        flow.response = Some(response);

        let stage = CspStage;
        stage.on_response_finalized(&mut flow).await.unwrap();

        let rewritten = flow
            .response
            .as_ref()
            .unwrap()
            .headers
            .get(CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(rewritten.contains("script-src 'self' 'unsafe-inline' https://cdn.example 'nonce-fresh123'"));
        assert!(rewritten.contains("worker-src 'self' https://cdn.example blob:"));
        assert!(!rewritten.contains("script-src-elem 'nonce-fresh123'"));
    }

    #[tokio::test]
    async fn on_response_finalized_does_not_touch_csp_when_injection_did_not_run() {
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.csp_nonce = Some("fresh123".to_string());

        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("script-src 'self' 'unsafe-inline' https://cdn.example"),
        );
        flow.response = Some(response);

        let stage = CspStage;
        stage.on_response_finalized(&mut flow).await.unwrap();

        assert_eq!(
            flow.response
                .as_ref()
                .unwrap()
                .headers
                .get(CONTENT_SECURITY_POLICY)
                .unwrap(),
            &HeaderValue::from_static("script-src 'self' 'unsafe-inline' https://cdn.example")
        );
    }

    #[tokio::test]
    async fn on_response_finalized_clones_default_src_when_script_src_is_missing() {
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.script_injected = true;
        flow.metadata.csp_nonce = Some("fresh123".to_string());

        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self' https://cdn.example; connect-src 'self'"),
        );
        flow.response = Some(response);

        let stage = CspStage;
        stage.on_response_finalized(&mut flow).await.unwrap();

        let rewritten = flow
            .response
            .as_ref()
            .unwrap()
            .headers
            .get(CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(rewritten.contains("default-src 'self' https://cdn.example"));
        assert!(rewritten.contains("script-src 'self' https://cdn.example 'nonce-fresh123'"));
        assert!(rewritten.contains("worker-src 'self' https://cdn.example blob:"));
        assert!(!rewritten.contains("script-src-elem 'nonce-fresh123'"));
    }

    #[tokio::test]
    async fn on_response_finalized_appends_blob_to_existing_worker_src() {
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.script_injected = true;
        flow.metadata.csp_nonce = Some("fresh123".to_string());

        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; worker-src 'self' https://workers.example"),
        );
        flow.response = Some(response);

        let stage = CspStage;
        stage.on_response_finalized(&mut flow).await.unwrap();

        let rewritten = flow
            .response
            .as_ref()
            .unwrap()
            .headers
            .get(CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(rewritten.contains("worker-src 'self' https://workers.example blob:"));
    }

    #[test]
    fn report_only_policy_remains_untouched() {
        let mut flow = Flow::new(RequestParts::default());
        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_SECURITY_POLICY_REPORT_ONLY,
            HeaderValue::from_static("script-src 'self'; connect-src 'none'"),
        );
        flow.response = Some(response);

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
