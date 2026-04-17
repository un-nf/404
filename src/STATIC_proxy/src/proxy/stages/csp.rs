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
use http::header::{HeaderValue, CONTENT_SECURITY_POLICY};
use rand::{rngs::OsRng, RngCore};

use crate::proxy::flow::Flow;

use super::FlowStage;

/// Sites where CSP should not be modified (they are bypassed from JS injection 
/// and have their own strict CSP requirements for dynamic module loading) -- WORKAROUND ONLY - these sites should be audited and removed from this list where possible
/// Though, privacy respecting sites like DuckDuckGo and Tutanota are expected to not require script injection, so they may be permanent members of this list.
const CSP_PASSTHROUGH_HOSTS: &[&str] = &[
    "duckduckgo.com",
    "duck.ai",
    "tuta.com",
    "tutanota.com",
];

#[derive(Clone, Default)]
pub struct CspStage;

#[async_trait]
impl FlowStage for CspStage {
    async fn on_response_headers(&self, flow: &mut Flow) -> Result<()> {
        // Don't process CSP for sites that have dynamic module requirements
        if should_skip_csp_processing(flow) {
            return Ok(());
        }

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

        flow.metadata.csp_nonce = Some(generate_nonce());
        Ok(())
    }

    async fn on_response_finalized(&self, flow: &mut Flow) -> Result<()> {
        // Don't process CSP for sites that have dynamic module requirements
        if should_skip_csp_processing(flow) {
            return Ok(());
        }

        let nonce = match flow.metadata.csp_nonce.clone() {
            Some(nonce) => nonce,
            None => return Ok(()),
        };

        if flow.metadata.script_hashes.is_empty() {
            return Ok(());
        }

        let response = match flow.response.as_mut() {
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

        response.headers.remove(CONTENT_SECURITY_POLICY);

        for value in csp_values {
            let rewritten = append_nonce_to_csp(&value, &nonce);
            let header_value = HeaderValue::from_str(&rewritten)
                .with_context(|| format!("invalid CSP after nonce append: {rewritten}"))?;
            response.headers.append(CONTENT_SECURITY_POLICY, header_value);
        }

        Ok(())
    }
}

fn generate_nonce() -> String {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    STANDARD_NO_PAD.encode(buf)
}

fn should_skip_csp_processing(flow: &Flow) -> bool {
    let Some(host) = flow.request.uri.host() else {
        return false;
    };

    CSP_PASSTHROUGH_HOSTS.iter().any(|suffix| {
        host == *suffix || host.ends_with(&format!(".{suffix}"))
    })
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

fn append_nonce_to_csp(csp: &str, nonce: &str) -> String {
    let nonce_token = format!("'nonce-{}'", nonce);
    let directives: Vec<&str> = csp.split(';').collect();
    let mut found = false;
    let mut fallback_default_src = None;

    let rewritten: Vec<String> = directives
        .iter()
        .enumerate()
        .map(|(index, directive)| {
            let trimmed = directive.trim();
            if trimmed.is_empty() {
                return String::new();
            }

            let name = trimmed
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();

            if name == "default-src" && fallback_default_src.is_none() {
                fallback_default_src = Some(index);
            }

            if (name == "script-src-elem" || name == "script-src") && !found {
                found = true;
                if trimmed.contains(&nonce_token) {
                    return trimmed.to_string();
                }
                return format!("{} {}", trimmed, nonce_token);
            }

            trimmed.to_string()
        })
        .collect();

    if found {
        return rewritten
            .into_iter()
            .filter(|directive| !directive.is_empty())
            .collect::<Vec<_>>()
            .join("; ");
    }

    rewritten
        .into_iter()
        .enumerate()
        .filter_map(|(index, directive)| {
            if directive.is_empty() {
                return None;
            }

            if Some(index) == fallback_default_src {
                if directive.contains(&nonce_token) {
                    return Some(directive);
                }
                return Some(format!("{} {}", directive, nonce_token));
            }

            Some(directive)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::{Flow, RequestParts, ResponseParts};
    use http::header::CONTENT_SECURITY_POLICY_REPORT_ONLY;

    #[test]
    fn append_nonce_prefers_script_src_elem() {
        let rewritten = append_nonce_to_csp(
            "default-src 'self'; script-src-elem 'self' https://cdn.example; object-src 'none'",
            "abc123",
        );

        assert!(rewritten.contains("default-src 'self'"));
        assert!(rewritten.contains("script-src-elem 'self' https://cdn.example 'nonce-abc123'"));
        assert!(rewritten.contains("object-src 'none'"));
    }

    #[test]
    fn append_nonce_falls_back_to_script_src() {
        let rewritten = append_nonce_to_csp("script-src 'self' https://cdn.example", "abc123");

        assert_eq!(rewritten, "script-src 'self' https://cdn.example 'nonce-abc123'");
    }

    #[test]
    fn append_nonce_falls_back_to_default_src_when_needed() {
        let rewritten = append_nonce_to_csp("default-src 'self' https://cdn.example; object-src 'none'", "abc123");

        assert!(rewritten.contains("default-src 'self' https://cdn.example 'nonce-abc123'"));
        assert!(rewritten.contains("object-src 'none'"));
    }

    #[test]
    fn append_nonce_keeps_existing_nonce() {
        let rewritten = append_nonce_to_csp(
            "script-src-elem 'self' 'nonce-origin123' https://cdn.example",
            "origin123",
        );

        assert_eq!(rewritten, "script-src-elem 'self' 'nonce-origin123' https://cdn.example");
    }

    #[test]
    fn extract_existing_nonce_reads_script_directives_only() {
        assert_eq!(
            extract_existing_nonce("default-src 'self'; script-src 'self' 'nonce-origin123' https://cdn.example"),
            Some("origin123".to_string())
        );
        assert_eq!(extract_existing_nonce("default-src 'self' 'nonce-ignoreme'"), None);
    }

    #[tokio::test]
    async fn on_response_headers_captures_nonce_without_rewriting_policy() {
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
    async fn on_response_finalized_rewrites_csp_only_after_injection() {
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.csp_nonce = Some("fresh123".to_string());
        flow.metadata.script_hashes = vec!["loader-hash".to_string()];

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
            &HeaderValue::from_static("script-src 'self' 'unsafe-inline' https://cdn.example 'nonce-fresh123'")
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

    #[test]
    fn skips_csp_processing_for_tutanota_hosts() {
        let flow = Flow::new(RequestParts {
            uri: http::Uri::from_static("https://mail.tutanota.com/"),
            ..RequestParts::default()
        });
        assert!(should_skip_csp_processing(&flow));

        let flow = Flow::new(RequestParts {
            uri: http::Uri::from_static("https://app.tuta.com/"),
            ..RequestParts::default()
        });
        assert!(should_skip_csp_processing(&flow));
    }

    #[test]
    fn skips_csp_processing_for_duckduckgo_hosts() {
        let flow = Flow::new(RequestParts {
            uri: http::Uri::from_static("https://duckduckgo.com/"),
            ..RequestParts::default()
        });
        assert!(should_skip_csp_processing(&flow));
    }

    #[test]
    fn does_not_skip_csp_processing_for_other_hosts() {
        let flow = Flow::new(RequestParts::default());
        assert!(!should_skip_csp_processing(&flow));
    }
}
