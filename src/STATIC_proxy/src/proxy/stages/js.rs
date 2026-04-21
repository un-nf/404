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
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use brotli::Decompressor;
use flate2::read::{GzDecoder, ZlibDecoder};
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use http::{HeaderName, HeaderValue};
use std::io::{Cursor, Read};
use zstd::stream::decode_all as zstd_decode_all;

use crate::proxy::flow::{Flow, ResponseParts};

use super::csp::{extract_existing_nonce, generate_proxy_nonce, rewrite_policy_for_injected_nonce};
use super::FlowStage;

const INJECTION_MARKER_HEADER: &str = "x-static-injected";
const RUNTIME_ASSET_PATH: &str = "/__static/runtime.js";

#[derive(Clone)]
pub struct JsInjectionStage {
    debug: bool,
    max_decompressed_html_bytes: usize,
}

impl JsInjectionStage {
    pub fn new(debug: bool, max_decompressed_html_bytes: usize) -> Self {
        Self {
            debug,
            max_decompressed_html_bytes,
        }
    }

    fn should_inject(&self, flow: &mut Flow) -> Result<bool> {
        let response = match flow.response.as_mut() {
            Some(resp) => resp,
            None => return Ok(false),
        };

        if !response.status.is_success() {
            return Ok(false);
        }

        if !self.prepare_html_body(response)? {
            return Ok(false);
        }

        if response.body.is_empty() {
            return Ok(false);
        }

        if let Ok(body_str) = std::str::from_utf8(response.body.as_bytes()) {
            if body_str.contains("__404_bootstrap_version")
                || body_str.contains("__STATIC_RUNTIME__")
                || body_str.contains("__static_profile")
            {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        Ok(true)
    }

    fn render_runtime_config(&self, flow: &Flow) -> String {
        serde_json::to_string(&flow.metadata.js_runtime_config)
            .unwrap_or_else(|_| "{}".to_string())
            .replace("</script>", "<\\/script>")
    }

    fn encode_runtime_config(&self, flow: &Flow) -> String {
        BASE64_STANDARD.encode(self.render_runtime_config(flow))
    }

    fn build_injection_block(&self, flow: &Flow) -> String {
        let config_b64 = self.encode_runtime_config(flow);

        let nonce_attr = flow
            .metadata
            .csp_nonce
            .as_deref()
            .map(|nonce| format!(" nonce=\"{}\"", nonce))
            .unwrap_or_default();

        let mut block = String::with_capacity(config_b64.len() + 160);
        block.push_str("<script src=\"");
        block.push_str(RUNTIME_ASSET_PATH);
        block.push_str("\" data-static-config-b64=\"");
        block.push_str(&config_b64);
        block.push_str("\"");
        block.push_str(&nonce_attr);
        block.push_str("></script>\n");

        block
    }

    fn prepare_html_body(&self, response: &mut ResponseParts) -> Result<bool> {
        let content_type = response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|raw| raw.to_ascii_lowercase())
            .unwrap_or_default();

        if !content_type.contains("text/html") {
            return Ok(false);
        }

        if !self.ensure_plain_body(response)? {
            return Ok(false);
        }

        Ok(true)
    }

    fn ensure_plain_body(&self, response: &mut ResponseParts) -> Result<bool> {
        let Some(raw) = response.headers.get(CONTENT_ENCODING) else {
            return Ok(true);
        };
        let encodings: Vec<String> = raw
            .to_str()
            .unwrap_or_default()
            .split(',')
            .map(|token| token.trim().to_ascii_lowercase())
            .filter(|token| !token.is_empty() && token != "identity")
            .collect();

        if encodings.is_empty() {
            response.headers.remove(CONTENT_ENCODING);
            return Ok(true);
        }

        let mut decoded = response.body.as_bytes().to_vec();
        for encoding in encodings.into_iter().rev() {
            decoded = match encoding.as_str() {
                "gzip" | "x-gzip" => self.decode_gzip(&decoded)?,
                "deflate" => self.decode_deflate(&decoded)?,
                "br" => self.decode_brotli(&decoded)?,
                "zstd" | "zst" => self.decode_zstd(&decoded)?,
                other => {
                    tracing::debug!(encoding = %other, "js_injector: unsupported content-encoding");
                    return Ok(false);
                }
            };
        }

        response
            .body
            .replace_limited(&decoded, self.max_decompressed_html_bytes, "decompressed HTML response body")?;
        response.headers.remove(CONTENT_ENCODING);
        response.headers.remove(TRANSFER_ENCODING);
        let len_value = HeaderValue::from_str(&response.body.len().to_string())
            .context("invalid content-length after body decode")?;
        response.headers.insert(CONTENT_LENGTH, len_value);
        Ok(true)
    }

    fn decode_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        self.ensure_decompressed_limit(&out)?;
        Ok(out)
    }

    fn decode_deflate(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        self.ensure_decompressed_limit(&out)?;
        Ok(out)
    }

    fn decode_brotli(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cursor = Cursor::new(data);
        let mut decoder = Decompressor::new(cursor, 4096);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        self.ensure_decompressed_limit(&out)?;
        Ok(out)
    }

    fn decode_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        let decoded = zstd_decode_all(Cursor::new(data)).context("failed to decode zstd body")?;
        self.ensure_decompressed_limit(&decoded)?;
        Ok(decoded)
    }

    fn ensure_decompressed_limit(&self, data: &[u8]) -> Result<()> {
        if data.len() > self.max_decompressed_html_bytes {
            anyhow::bail!(
                "decompressed HTML response body exceeds configured limit of {} bytes",
                self.max_decompressed_html_bytes
            );
        }

        Ok(())
    }

    fn mark_injected_response(response: &mut ResponseParts) {
        response.headers.insert(
            HeaderName::from_static(INJECTION_MARKER_HEADER),
            HeaderValue::from_static("1"),
        );
    }

    fn choose_insertion_strategy(&self, body_lower: &str) -> InsertionStrategy {
        if let Some(idx) = Self::find_tag_end(body_lower, "<head") {
            return InsertionStrategy::InsideHead(idx);
        }
        if let Some(idx) = Self::find_tag_end(body_lower, "<html") {
            return InsertionStrategy::CreateHeadAt(idx);
        }
        if let Some(idx) = Self::find_doctype_end(body_lower) {
            return InsertionStrategy::CreateHeadAt(idx);
        }
        InsertionStrategy::PrependHead
    }

    fn find_tag_end(body_lower: &str, tag: &str) -> Option<usize> {
        let mut search_start = 0;
        while search_start < body_lower.len() {
            let haystack = &body_lower[search_start..];
            let relative = match haystack.find(tag) {
                Some(pos) => pos,
                None => break,
            };
            let idx = search_start + relative;
            let boundary = idx + tag.len();
            if boundary >= body_lower.len() {
                return None;
            }
            let next_char = body_lower.as_bytes()[boundary] as char;
            if next_char.is_ascii_alphanumeric() {
                search_start = boundary;
                continue;
            }
            if let Some(close_rel) = body_lower[boundary..].find('>') {
                return Some(boundary + close_rel + 1);
            } else {
                return None;
            }
        }
        None
    }

    fn find_doctype_end(body_lower: &str) -> Option<usize> {
        let idx = body_lower.find("<!doctype")?;
        let rel = body_lower[idx..].find('>')?;
        Some(idx + rel + 1)
    }

    fn prepare_meta_csp_nonce(flow: &mut Flow, body: &str) {
        if flow.metadata.csp_nonce.is_some() {
            return;
        }

        if let Some(nonce) = find_meta_csp_nonce(body) {
            flow.metadata.csp_nonce = Some(nonce);
            return;
        }

        if has_meta_csp(body) {
            flow.metadata.csp_nonce = Some(generate_proxy_nonce());
        }
    }

    fn rewrite_meta_csp(body: &str, nonce: &str) -> String {
        rewrite_meta_csp_tags(body, nonce)
    }
}

#[derive(Clone, Debug)]
struct HtmlAttrMatch {
    full_range: std::ops::Range<usize>,
    value: String,
    quote: Option<char>,
}

fn has_meta_csp(body: &str) -> bool {
    find_meta_csp_tag_ranges(body)
        .into_iter()
        .any(|(start, end)| is_csp_meta_tag(&body[start..end]))
}

fn find_meta_csp_nonce(body: &str) -> Option<String> {
    for (start, end) in find_meta_csp_tag_ranges(body) {
        let tag = &body[start..end];
        if !is_csp_meta_tag(tag) {
            continue;
        }

        let Some(content) = find_html_attr(tag, "content") else {
            continue;
        };

        if let Some(nonce) = extract_existing_nonce(&content.value) {
            return Some(nonce);
        }
    }

    None
}

fn rewrite_meta_csp_tags(body: &str, nonce: &str) -> String {
    let tag_ranges = find_meta_csp_tag_ranges(body);
    if tag_ranges.is_empty() {
        return body.to_string();
    }

    let mut rewritten = String::with_capacity(body.len() + 128);
    let mut cursor = 0;

    for (start, end) in tag_ranges {
        rewritten.push_str(&body[cursor..start]);
        let tag = &body[start..end];
        rewritten.push_str(&rewrite_meta_csp_tag(tag, nonce));
        cursor = end;
    }

    rewritten.push_str(&body[cursor..]);
    rewritten
}

fn rewrite_meta_csp_tag(tag: &str, nonce: &str) -> String {
    if !is_csp_meta_tag(tag) {
        return tag.to_string();
    }

    let Some(content_attr) = find_html_attr(tag, "content") else {
        return tag.to_string();
    };

    let rewritten_policy = rewrite_policy_for_injected_nonce(&content_attr.value, nonce);
    let replacement = match content_attr.quote {
        Some('\'') => format!("content='{}'", escape_single_quoted_html_attr(&rewritten_policy)),
        _ => format!("content=\"{}\"", escape_double_quoted_html_attr(&rewritten_policy)),
    };

    let mut rewritten = String::with_capacity(tag.len() + replacement.len());
    rewritten.push_str(&tag[..content_attr.full_range.start]);
    rewritten.push_str(&replacement);
    rewritten.push_str(&tag[content_attr.full_range.end..]);
    rewritten
}

fn find_meta_csp_tag_ranges(body: &str) -> Vec<(usize, usize)> {
    let body_lower = body.to_ascii_lowercase();
    let mut matches = Vec::new();
    let mut search_start = 0;

    while search_start < body_lower.len() {
        let Some(relative) = body_lower[search_start..].find("<meta") else {
            break;
        };
        let start = search_start + relative;
        let Some(end) = find_html_tag_end(body, start) else {
            break;
        };
        matches.push((start, end));
        search_start = end;
    }

    matches
}

fn find_html_tag_end(body: &str, tag_start: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut idx = tag_start;
    let mut quote: Option<u8> = None;

    while idx < bytes.len() {
        let byte = bytes[idx];
        if let Some(active_quote) = quote {
            if byte == active_quote {
                quote = None;
            }
        } else if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
        } else if byte == b'>' {
            return Some(idx + 1);
        }
        idx += 1;
    }

    None
}

fn is_csp_meta_tag(tag: &str) -> bool {
    find_html_attr(tag, "http-equiv")
        .map(|attr| attr.value.eq_ignore_ascii_case("content-security-policy"))
        .unwrap_or(false)
}

fn find_html_attr(tag: &str, target_name: &str) -> Option<HtmlAttrMatch> {
    let bytes = tag.as_bytes();
    let mut idx = 0;

    while idx < bytes.len() && bytes[idx] != b'<' {
        idx += 1;
    }
    if idx < bytes.len() {
        idx += 1;
    }
    while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() && bytes[idx] != b'>' {
        idx += 1;
    }

    while idx < bytes.len() {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() || bytes[idx] == b'>' || bytes[idx] == b'/' {
            break;
        }

        let name_start = idx;
        while idx < bytes.len()
            && !bytes[idx].is_ascii_whitespace()
            && bytes[idx] != b'='
            && bytes[idx] != b'>'
        {
            idx += 1;
        }
        let name_end = idx;

        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }

        let mut value = String::new();
        let mut quote = None;
        if idx < bytes.len() && bytes[idx] == b'=' {
            idx += 1;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            if idx < bytes.len() && (bytes[idx] == b'"' || bytes[idx] == b'\'') {
                quote = Some(bytes[idx] as char);
                let quoted = bytes[idx];
                idx += 1;
                let value_start = idx;
                while idx < bytes.len() && bytes[idx] != quoted {
                    idx += 1;
                }
                value = tag[value_start..idx].to_string();
                if idx < bytes.len() {
                    idx += 1;
                }
            } else {
                let value_start = idx;
                while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() && bytes[idx] != b'>' {
                    idx += 1;
                }
                value = tag[value_start..idx].to_string();
            }
        }

        let name = &tag[name_start..name_end];
        if name.eq_ignore_ascii_case(target_name) {
            return Some(HtmlAttrMatch {
                full_range: name_start..idx,
                value,
                quote,
            });
        }
    }

    None
}

fn escape_double_quoted_html_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
}

fn escape_single_quoted_html_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('\'', "&#39;")
        .replace('<', "&lt;")
}

enum InsertionStrategy {
    InsideHead(usize),
    CreateHeadAt(usize),
    BeforeScript(usize),
    PrependHead,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::RequestParts;
    use serde_json::json;
    use zstd::stream::encode_all as zstd_encode_all;

    #[test]
    fn render_runtime_config_escapes_script_terminator() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.js_runtime_config = json!({
            "value": "before </script> after",
        });

        let rendered = stage.render_runtime_config(&flow);

        assert!(rendered.contains("before <\\/script> after"));
        assert!(!rendered.contains("</script>"));
    }

    #[test]
    fn build_injection_block_emits_config_and_runtime() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.csp_nonce = Some("nonce-123".to_string());
        flow.metadata.js_runtime_config = json!({
            "fingerprint": {
                "platform": "Windows",
            },
        });

        let block = stage.build_injection_block(&flow);

        assert!(block.contains("<script src=\"/__static/runtime.js\""));
        assert!(block.contains("data-static-config-b64=\""));
        assert!(block.contains(" nonce=\"nonce-123\""));
    }

    #[tokio::test]
    async fn on_response_body_injects_runtime_block_and_marks_injection() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.csp_nonce = Some("nonce-abc".to_string());
        flow.metadata.js_runtime_config = json!({
            "value": "</script>",
        });

        let mut response = ResponseParts::default();
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        response.body.replace(b"<!doctype html><html><head><title>x</title></head><body>ok</body></html>");
        flow.response = Some(response);

        stage.on_response_body(&mut flow).await.unwrap();

        let body = std::str::from_utf8(flow.response.as_ref().unwrap().body.as_bytes()).unwrap();
        assert!(body.contains("<script src=\"/__static/runtime.js\""));
        assert!(body.contains(" nonce=\"nonce-abc\""));
        assert!(body.contains("data-static-config-b64=\""));
        assert!(flow.metadata.script_injected);
        let response = flow.response.as_ref().unwrap();
        assert_eq!(response.headers.get(HeaderName::from_static(INJECTION_MARKER_HEADER)).and_then(|value| value.to_str().ok()), Some("1"));
    }

    #[tokio::test]
    async fn on_response_body_injects_before_first_script_when_script_precedes_head() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        let mut flow = Flow::new(RequestParts::default());

        let mut response = ResponseParts::default();
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        response.body.replace(b"<!doctype html><html><script>window.pageFirst = true;</script><head><title>x</title></head><body>ok</body></html>");
        flow.response = Some(response);

        stage.on_response_body(&mut flow).await.unwrap();

        let body = std::str::from_utf8(flow.response.as_ref().unwrap().body.as_bytes()).unwrap();
        let injected_idx = body.find("<script src=\"/__static/runtime.js\"").unwrap();
        let page_script_idx = body.find("<script>window.pageFirst = true;</script>").unwrap();
        assert!(injected_idx < page_script_idx);
    }

    #[tokio::test]
    async fn on_response_body_injects_before_existing_head_script() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        let mut flow = Flow::new(RequestParts::default());

        let mut response = ResponseParts::default();
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        response.body.replace(b"<!doctype html><html><head><script src=\"/app.js\"></script><title>x</title></head><body>ok</body></html>");
        flow.response = Some(response);

        stage.on_response_body(&mut flow).await.unwrap();

        let body = std::str::from_utf8(flow.response.as_ref().unwrap().body.as_bytes()).unwrap();
        let injected_idx = body.find("<script src=\"/__static/runtime.js\"").unwrap();
        let page_script_idx = body.find("<script src=\"/app.js\"></script>").unwrap();
        assert!(injected_idx < page_script_idx);
    }

    #[tokio::test]
    async fn on_response_body_decodes_zstd_html_and_injects_runtime() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        let mut flow = Flow::new(RequestParts::default());

        let html = b"<!doctype html><html><head><title>x</title></head><body>ok</body></html>";
        let encoded = zstd_encode_all(Cursor::new(html), 0).unwrap();

        let mut response = ResponseParts::default();
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        response.headers.insert(CONTENT_ENCODING, HeaderValue::from_static("zstd"));
        response.body.replace(&encoded);
        flow.response = Some(response);

        stage.on_response_body(&mut flow).await.unwrap();

        let response = flow.response.as_ref().unwrap();
        let body = std::str::from_utf8(response.body.as_bytes()).unwrap();
        assert!(body.contains("<script src=\"/__static/runtime.js\""));
        assert!(response.headers.get(CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn on_response_body_rewrites_meta_csp_and_reuses_existing_nonce() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.js_runtime_config = json!({});

        let mut response = ResponseParts::default();
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        response.body.replace(
            b"<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self' 'nonce-origin123'; worker-src 'self'\"><script src=\"/app.js\"></script></head><body>ok</body></html>",
        );
        flow.response = Some(response);

        stage.on_response_body(&mut flow).await.unwrap();

        let body = std::str::from_utf8(flow.response.as_ref().unwrap().body.as_bytes()).unwrap();
        assert!(body.contains("nonce=\"origin123\""));
        assert!(body.contains("worker-src 'self' blob:"));
        assert_eq!(flow.metadata.csp_nonce.as_deref(), Some("origin123"));
    }

    #[tokio::test]
    async fn on_response_body_generates_nonce_for_meta_csp_without_one() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        let mut flow = Flow::new(RequestParts::default());
        flow.metadata.js_runtime_config = json!({});

        let mut response = ResponseParts::default();
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        response.body.replace(
            b"<!doctype html><html><head><meta http-equiv=\"content-security-policy\" content=\"default-src 'self'; worker-src 'self'\"></head><body>ok</body></html>",
        );
        flow.response = Some(response);

        stage.on_response_body(&mut flow).await.unwrap();

        let nonce = flow.metadata.csp_nonce.clone().expect("meta CSP should produce a nonce");
        let body = std::str::from_utf8(flow.response.as_ref().unwrap().body.as_bytes()).unwrap();
        assert!(body.contains(&format!("nonce=\"{nonce}\"")));
        assert!(body.contains(&format!("script-src 'self' 'nonce-{nonce}'")));
        assert!(body.contains("worker-src 'self' blob:"));
    }

    #[tokio::test]
    async fn on_response_body_rejects_oversized_decompressed_html() {
        let stage = JsInjectionStage::new(false, 32);
        let mut flow = Flow::new(RequestParts::default());

        let html = b"<!doctype html><html><head><title>x</title></head><body>this body is intentionally too large</body></html>";
        let encoded = zstd_encode_all(Cursor::new(html), 0).unwrap();

        let mut response = ResponseParts::default();
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        response.headers.insert(CONTENT_ENCODING, HeaderValue::from_static("zstd"));
        response.body.replace(&encoded);
        flow.response = Some(response);

        let err = stage
            .on_response_body(&mut flow)
            .await
            .expect_err("oversized decompressed HTML should fail");

        assert!(err.to_string().contains("decompressed HTML response body exceeds configured limit"));
    }
}

#[async_trait]
impl FlowStage for JsInjectionStage {

    async fn on_response_body(&self, flow: &mut Flow) -> Result<()> {
        if !self.should_inject(flow)? {
            return Ok(());
        }

        let body_owned = {
            let response_ref = flow
                .response
                .as_ref()
                .expect("response checked in should_inject");
            std::str::from_utf8(response_ref.body.as_bytes())?.to_owned()
        };

        Self::prepare_meta_csp_nonce(flow, &body_owned);

        let injection_block = self.build_injection_block(flow);

        let response = flow
            .response
            .as_mut()
            .expect("response checked in should_inject");

        let body = body_owned;
        let body_lower = body.to_ascii_lowercase();
        let mut strategy = self.choose_insertion_strategy(&body_lower);
        if let Some(script_idx) = body_lower.find("<script") {
            strategy = InsertionStrategy::BeforeScript(script_idx);
        }
        let wrapped_block = format!("<head>\n{}\n</head>\n", injection_block);

        let mut mutated = String::with_capacity(body.len() + wrapped_block.len());
        match strategy {
            InsertionStrategy::InsideHead(idx) => {
                let safe_idx = idx.min(body.len());
                let (head, tail) = body.split_at(safe_idx);
                mutated.push_str(head);
                mutated.push_str(&injection_block);
                mutated.push_str(tail);
            }
            InsertionStrategy::CreateHeadAt(idx) => {
                let safe_idx = idx.min(body.len());
                let (head, tail) = body.split_at(safe_idx);
                mutated.push_str(head);
                mutated.push_str(&wrapped_block);
                mutated.push_str(tail);
            }
            InsertionStrategy::BeforeScript(idx) => {
                let safe_idx = idx.min(body.len());
                let (head, tail) = body.split_at(safe_idx);
                mutated.push_str(head);
                mutated.push_str(&injection_block);
                mutated.push_str(tail);
            }
            InsertionStrategy::PrependHead => {
                mutated.push_str(&wrapped_block);
                mutated.push_str(&body);
            }
        }

        if let Some(nonce) = flow.metadata.csp_nonce.as_deref() {
            mutated = Self::rewrite_meta_csp(&mutated, nonce);
        }

        response.body.replace(mutated.as_bytes());
        Self::mark_injected_response(response);
        flow.metadata.script_injected = true;

        if self.debug {
            tracing::debug!(%flow.id, "js_injection_applied" = true, bytes_added = injection_block.len());
        }

        Ok(())
    }
}
