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
use http::header::CONTENT_SECURITY_POLICY;

use crate::proxy::flow::Flow;

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

        for value in &csp_values {
            if let Some(nonce) = extract_existing_nonce(value) {
                flow.metadata.csp_nonce = Some(nonce);
                return Ok(());
            }
        }

        Ok(())
    }

    async fn on_response_finalized(&self, _flow: &mut Flow) -> Result<()> {
        Ok(())
    }
}

fn extract_existing_nonce(csp: &str) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::{Flow, RequestParts, ResponseParts};
    use http::HeaderValue;
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
    async fn on_response_headers_keeps_policy_unchanged_without_origin_nonce() {
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
        assert!(flow.metadata.csp_nonce.is_none());
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
    async fn on_response_finalized_leaves_csp_unchanged_after_injection() {
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.script_injected = true;

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
