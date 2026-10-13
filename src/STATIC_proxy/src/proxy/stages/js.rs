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
use zstd::stream::read::Decoder as ZstdDecoder;

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

    fn inject_worker(&self, flow: &mut Flow) -> Result<bool> {
        let destination = flow.request.headers.get("sec-fetch-dest")
            .and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
        if !matches!(destination.as_str(), "worker" | "sharedworker" | "serviceworker") {
            return Ok(false);
        }
        if flow.metadata.worker_injected { return Ok(true); }
        flow.metadata.worker_coverage = Some("unavailable: response prerequisites".into());
        let mode = flow.request.headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !matches!(mode, "cors" | "same-origin") { return Ok(true); }
        let fingerprint = flow.metadata.js_runtime_config.get("fingerprint").unwrap_or(&flow.metadata.js_runtime_config);
        if !fingerprint.get("user_agent").is_some_and(|v| v.is_string()) { return Ok(true); }
        crate::runtime_schema::validate_fingerprint(fingerprint)?;
        let profile_json = serde_json::to_string(&worker_profile(fingerprint))?;
        let Some(response) = flow.response.as_mut() else { return Ok(true); };
        if response.status != http::StatusCode::OK { return Ok(true); }
        let mime = response.headers.get(CONTENT_TYPE).and_then(|x| x.to_str().ok())
            .unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if !matches!(mime.as_str(), "text/javascript" | "application/javascript" | "application/ecmascript" | "text/ecmascript") {
            return Ok(true);
        }
        if !self.ensure_plain_body(response)? { return Ok(true); }
        let Ok(source) = std::str::from_utf8(response.body.as_bytes()) else { return Ok(true); };
        if source.len() > 2 * 1024 * 1024 {
            flow.metadata.worker_coverage = Some("unsupported: worker parser size budget".into());
            return Ok(true);
        }
        let Some((index, module)) = worker_prelude(source) else {
            flow.metadata.worker_coverage = Some("unsupported: source syntax not supported by parser".into());
            return Ok(true);
        };
        if module && !permits_worker_bootstrap_import(&response.headers) {
            flow.metadata.worker_coverage = Some("unsupported: worker CSP disallows bootstrap import".into());
            return Ok(true);
        }
        let bootstrap = if module {
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile_json.as_bytes());
            let url = format!("/__static/worker-module.js?profile={encoded}");
            format!("import {};\n", serde_json::to_string(&url)?)
        } else {
            format!(";{}({});\n", crate::assets::ScriptBundle::load().worker_classic, profile_json)
        };
        let mut rewritten = String::with_capacity(source.len() + bootstrap.len());
        rewritten.push_str(&source[..index]);
        rewritten.push_str("\n");
        rewritten.push_str(&bootstrap);
        rewritten.push_str(&source[index..]);
        response.body.replace_limited(rewritten.as_bytes(), self.max_decompressed_html_bytes, "rewritten worker body")?;
        for key in ["etag", "last-modified", "content-md5", "digest", "content-digest", "repr-digest"] {
            response.headers.remove(key);
        }
        response.headers.insert(CONTENT_LENGTH, HeaderValue::from_str(&response.body.len().to_string())?);
        flow.metadata.worker_injected = true;
        flow.metadata.worker_coverage = Some(format!("{destination}: selected surfaces bootstrap inserted; execution unverified"));
        Ok(true)
    }

    fn should_inject(&self, flow: &mut Flow) -> Result<bool> {
        if flow.metadata.script_injected {
            return Ok(false);
        }

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

        if std::str::from_utf8(response.body.as_bytes()).is_err() {
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
        self.read_decompressed_limited(&mut decoder)
    }

    fn decode_deflate(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(data);
        self.read_decompressed_limited(&mut decoder)
    }

    fn decode_brotli(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cursor = Cursor::new(data);
        let mut decoder = Decompressor::new(cursor, 4096);
        self.read_decompressed_limited(&mut decoder)
    }

    fn decode_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZstdDecoder::new(Cursor::new(data)).context("failed to decode zstd body")?;
        self.read_decompressed_limited(&mut decoder)
    }

    fn read_decompressed_limited<R: Read>(&self, reader: &mut R) -> Result<Vec<u8>> {
        let mut decoded = Vec::new();
        let mut chunk = [0u8; 8192];

        loop {
            let read = reader.read(&mut chunk)?;
            if read == 0 {
                break;
            }

            if read > self.max_decompressed_html_bytes.saturating_sub(decoded.len()) {
                anyhow::bail!(
                    "decompressed HTML response body exceeds configured limit of {} bytes",
                    self.max_decompressed_html_bytes
                );
            }

            decoded.extend_from_slice(&chunk[..read]);
        }

        Ok(decoded)
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

fn permits_worker_bootstrap_import(headers: &http::HeaderMap) -> bool {
    headers.get_all(http::header::CONTENT_SECURITY_POLICY).iter().all(|policy| {
        let Ok(policy) = policy.to_str() else { return false; };
        let mut script = None;
        let mut default = None;
        for directive in policy.split(';') {
            let mut parts = directive.split_whitespace();
            match parts.next().unwrap_or("").to_ascii_lowercase().as_str() {
                "script-src" if script.is_none() => script = Some(parts.collect::<Vec<_>>()),
                "default-src" if default.is_none() => default = Some(parts.collect::<Vec<_>>()),
                _ => {}
            }
        }
        let Some(tokens) = script.or(default) else { return true; };
        !tokens.contains(&"'strict-dynamic'") &&
            tokens.iter().any(|token| *token == "'self'" || *token == "*")
    })
}

fn worker_profile(fingerprint: &serde_json::Value) -> serde_json::Value {
    let mut profile = serde_json::Map::new();
    for key in ["user_agent", "platform", "vendor", "vendorSub", "productSub", "browser_family",
        "browser_variant", "profile_variant", "browser_type", "browser_version", "oscpu", "buildID",
        "hardware_concurrency", "device_memory", "max_touch_points", "languages", "language",
        "do_not_track", "pdf_viewer_enabled", "ua_data", "sec_ch_ua_platform", "enable_network_spoof",
        "downlink", "rtt", "effective_type", "connection_type", "timezone", "enable_timezone_spoof",
        "enable_performance_spoof", "enable_webgl_spoof", "webgl_vendor", "webgl_renderer",
        "webgl_parameters", "webgl_standard_vendor", "webgl_standard_renderer",
        "storage_quota", "storage_usage", "storage_usage_quantum", "enable_storage_spoof",
        "permission_states", "enable_geolocation_spoof", "media_capabilities", "cookie_enabled", "save_data",
        "enable_permissions_spoof", "enable_notifications_spoof", "enable_battery_spoof",
        "enable_media_capabilities_spoof", "compatibility_mode"] {
        if let Some(value) = fingerprint.get(key) { profile.insert(key.into(), value.clone()); }
    }
    serde_json::Value::Object(profile)
}

fn worker_prelude(source: &str) -> Option<(usize, bool)> {
    let allocator = oxc_allocator::Allocator::default();
    let parsed = oxc_parser::Parser::new(&allocator, source, oxc_span::SourceType::unambiguous()).parse();
    if !parsed.errors.is_empty() || parsed.panicked { return None; }
    let program = parsed.program;
    let module = program.source_type.is_module();
    let index = program.directives.last().map(|directive| directive.span.end as usize)
        .or_else(|| program.hashbang.as_ref().map(|hashbang| hashbang.span.end as usize))
        .unwrap_or(if source.starts_with('\u{feff}') { 3 } else { 0 });
    // The separator protects a hashbang or an ASI-terminated directive.
    Some((index, module))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::RequestParts;
    use brotli::CompressorWriter;
    use flate2::{Compression, write::{GzEncoder, ZlibEncoder}};
    use serde_json::json;
    use std::io::Write;
    use zstd::stream::encode_all as zstd_encode_all;

    fn worker_flow(destination: &str, mode: &str, source: &str) -> Flow {
        let mut request = RequestParts::default();
        request.uri = "https://fixture.test/worker.js".parse().unwrap();
        request.headers.insert("sec-fetch-dest", HeaderValue::from_str(destination).unwrap());
        request.headers.insert("sec-fetch-mode", HeaderValue::from_str(mode).unwrap());
        let mut flow = Flow::new(request);
        let profile_source = match std::env::var("STATIC_BROWSER_PROFILE").as_deref() {
            Ok("firefox") => include_str!("../../../profiles/firefox-windows.json"),
            Ok("edge") => include_str!("../../../profiles/edge-windows.json"),
            _ => include_str!("../../../profiles/chrome-windows.json"),
        };
        let profile: serde_json::Value = serde_json::from_str(profile_source).unwrap();
        flow.metadata.js_runtime_config = json!({ "fingerprint": profile["fingerprint"], "startup_salt": "must-not-be-published" });
        let mut response = ResponseParts::default();
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/javascript"));
        response.body.replace(source.as_bytes());
        flow.response = Some(response);
        flow
    }

    #[tokio::test]
    async fn workers_preserve_directives_and_deduplicate_trusted_flow() {
        for destination in ["worker", "sharedworker", "serviceworker"] {
            let mut flow = worker_flow(destination, "same-origin", "/* leading */ 'use strict';\npostMessage(location.href);");
            let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
            stage.on_response_body(&mut flow).await.unwrap();
            let first = flow.response.as_ref().unwrap().body.as_bytes().to_vec();
            let source = std::str::from_utf8(&first).unwrap();
            assert!(source.starts_with("/* leading */ 'use strict';"));
            assert!(!source.contains("must-not-be-published"));
            assert!(!source.contains("chrome_win10_canvas_v1"));
            assert!(flow.metadata.worker_injected);
            assert!(!flow.metadata.script_injected);
            stage.on_response_body(&mut flow).await.unwrap();
            assert_eq!(flow.response.as_ref().unwrap().body.as_bytes(), first.as_slice());
        }
    }

    #[tokio::test]
    async fn module_worker_bootstrap_import_precedes_application_imports() {
        let mut flow = worker_flow("worker", "same-origin", "import './dependency.js';\npostMessage(navigator.userAgent);");
        JsInjectionStage::new(false, 16 * 1024 * 1024).on_response_body(&mut flow).await.unwrap();
        let source = std::str::from_utf8(flow.response.as_ref().unwrap().body.as_bytes()).unwrap();
        assert!(source.starts_with("\nimport \"/__static/worker-module.js?profile="));
        assert!(source.ends_with("import './dependency.js';\npostMessage(navigator.userAgent);"));
    }

    #[test]
    fn worker_parser_preserves_directives_and_distinguishes_module_syntax() {
        let source = "#!worker\n'use strict'; doWork()";
        let (index, module) = worker_prelude(source).unwrap();
        assert!(source[..index].contains("'use strict'"));
        assert!(!module);
        assert!(worker_prelude("'use strict'\ndoWork()").is_some());
        assert!(worker_prelude("import './dependency.js';").unwrap().1);
        assert!(!worker_prelude("const text = 'import ./dependency.js';").unwrap().1);
        assert!(worker_prelude("/* unterminated").is_none());
        assert!(worker_prelude("'unterminated").is_none());
    }

    #[tokio::test]
    async fn worker_skip_cases_report_unavailable_without_changing_source() {
        for (mode, mime) in [("no-cors", "text/javascript"), ("same-origin", "text/plain")] {
            let mut flow = worker_flow("worker", mode, "postMessage('native')");
            flow.response.as_mut().unwrap().headers.insert(CONTENT_TYPE, HeaderValue::from_str(mime).unwrap());
            JsInjectionStage::new(false, 16 * 1024 * 1024).on_response_body(&mut flow).await.unwrap();
            assert!(!flow.metadata.worker_injected);
            assert_eq!(flow.response.as_ref().unwrap().body.as_bytes(), b"postMessage('native')");
            assert!(flow.metadata.worker_coverage.is_some());
        }
    }

    #[tokio::test]
    async fn module_worker_csp_is_not_weakened_or_given_a_forbidden_import() {
        let mut flow = worker_flow("worker", "same-origin", "import './dependency.js';");
        flow.response.as_mut().unwrap().headers.insert(http::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("script-src https://cdn.example; worker-src 'none'"));
        JsInjectionStage::new(false, 16 * 1024 * 1024).on_response_body(&mut flow).await.unwrap();
        assert!(!flow.metadata.worker_injected);
        assert_eq!(flow.response.as_ref().unwrap().body.as_bytes(), b"import './dependency.js';");
        assert!(flow.metadata.worker_coverage.as_deref().unwrap().contains("CSP"));
    }

    #[tokio::test]
    async fn export_worker_browser_fixtures() {
        let Some(directory) = std::env::var_os("STATIC_BROWSER_FIXTURE_DIR") else { return; };
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        let fixtures = [
            ("classic.js", "worker", "same-origin", "'use strict';\nimportScripts('./helper.js'); readPrivacy().then(privacy=>postMessage({ua:navigator.userAgent, helper, href:location.href, privacy, strict:(function(){return this===undefined})()}));"),
            ("module.js", "worker", "cors", "import {snapshot} from './dependency.js'; readPrivacy().then(privacy=>postMessage({ua:navigator.userAgent, dependency:snapshot, href:import.meta.url, privacy}));"),
            ("shared.js", "sharedworker", "same-origin", "let count=0; onconnect=async e=>e.ports[0].postMessage({ua:navigator.userAgent,count:++count,href:location.href,privacy:await readPrivacy()});"),
            ("service.js", "serviceworker", "same-origin", "const initial=navigator.userAgent; onmessage=async e=>e.ports[0].postMessage({ua:initial,href:location.href,privacy:await readPrivacy()});"),
            ("service-module.js", "serviceworker", "cors", "import {snapshot} from './dependency.js'; onmessage=async e=>e.ports[0].postMessage({ua:navigator.userAgent,dependency:snapshot,href:import.meta.url,privacy:await readPrivacy()});"),
        ];
        for (name, destination, mode, source) in fixtures {
            let privacy_probe = r#"
              async function readPrivacy() {
                const result = {};
                if(navigator.storage) result.storage = await navigator.storage.estimate();
                if(typeof Notification === 'function') result.notification = Notification.permission;
                if(navigator.permissions) {
                  try {result.permission = (await navigator.permissions.query({name:'notifications'})).state}
                  catch(e) {result.permissionUnavailable = e.name}
                }
                if(navigator.mediaCapabilities) result.media = await navigator.mediaCapabilities.decodingInfo({
                  type:'file',audio:{contentType:'audio/webm; codecs="opus"',channels:'2',bitrate:128000,samplerate:48000}});
                return result;
              }
            "#;
            let source = format!("{source}\n{privacy_probe}");
            let mut flow = worker_flow(destination, mode, &source);
            JsInjectionStage::new(false, 16 * 1024 * 1024).on_response_body(&mut flow).await.unwrap();
            assert!(flow.metadata.worker_injected);
            std::fs::write(directory.join(name), flow.response.as_ref().unwrap().body.as_bytes()).unwrap();
        }
        std::fs::write(directory.join("worker-module.bundle.js"), crate::assets::ScriptBundle::load().worker_module.as_bytes()).unwrap();
        std::fs::write(directory.join("runtime.bundle.js"), crate::assets::ScriptBundle::load().runtime.as_bytes()).unwrap();
    }

    #[test]
    fn worker_profile_carries_privacy_observations_without_private_material() {
        let fingerprint = json!({"storage_quota": 107374182400u64,
            "storage_usage_quantum": 1048576, "enable_storage_spoof": false,
            "permission_states": {"camera":"denied"}, "media_capabilities":{"smooth":true},
            "canvas_hash":"private-seed", "startup_salt":"private-salt", "nonce":"private-nonce"});
        let profile = worker_profile(&fingerprint);
        for key in ["storage_quota", "storage_usage_quantum", "enable_storage_spoof", "permission_states", "media_capabilities"] {
            assert_eq!(profile[key], fingerprint[key]);
        }
        for key in ["canvas_hash", "startup_salt", "nonce"] { assert!(profile.get(key).is_none()); }
    }

    fn gzip_encode(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn deflate_encode(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli_encode(data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        {
            let mut encoder = CompressorWriter::new(&mut encoded, 4096, 5, 22);
            encoder.write_all(data).unwrap();
        }
        encoded
    }

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
    async fn origin_markers_do_not_suppress_injection_and_flow_injects_once() {
        let stage = JsInjectionStage::new(false, 16 * 1024 * 1024);
        for marker in ["__404_bootstrap_version", "__STATIC_RUNTIME__", "__static_profile"] {
            let mut flow = Flow::new(RequestParts::default());
            let mut response = ResponseParts::default();
            response.headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
            response.body.replace(format!("<html><head></head><body>{marker}</body></html>").as_bytes());
            flow.response = Some(response);

            stage.on_response_body(&mut flow).await.unwrap();
            assert!(flow.metadata.script_injected);
            let first = flow.response.as_ref().unwrap().body.as_bytes().to_vec();
            assert!(std::str::from_utf8(&first).unwrap().contains("data-static-config-b64"));

            stage.on_response_body(&mut flow).await.unwrap();
            assert_eq!(flow.response.as_ref().unwrap().body.as_bytes(), first.as_slice());
        }
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
        assert!(body.contains("worker-src 'self'"));
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
        assert!(body.contains("worker-src 'self'"));
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

    #[test]
    fn decode_gzip_rejects_oversized_decompressed_html() {
        let stage = JsInjectionStage::new(false, 32);
        let encoded = gzip_encode(b"this body is intentionally too large");

        let err = stage
            .decode_gzip(&encoded)
            .expect_err("oversized gzip body should fail");

        assert!(err.to_string().contains("decompressed HTML response body exceeds configured limit"));
    }

    #[test]
    fn decode_deflate_rejects_oversized_decompressed_html() {
        let stage = JsInjectionStage::new(false, 32);
        let encoded = deflate_encode(b"this body is intentionally too large");

        let err = stage
            .decode_deflate(&encoded)
            .expect_err("oversized deflate body should fail");

        assert!(err.to_string().contains("decompressed HTML response body exceeds configured limit"));
    }

    #[test]
    fn decode_brotli_rejects_oversized_decompressed_html() {
        let stage = JsInjectionStage::new(false, 32);
        let encoded = brotli_encode(b"this body is intentionally too large");

        let err = stage
            .decode_brotli(&encoded)
            .expect_err("oversized brotli body should fail");

        assert!(err.to_string().contains("decompressed HTML response body exceeds configured limit"));
    }

    #[test]
    fn decode_zstd_rejects_oversized_decompressed_html() {
        let stage = JsInjectionStage::new(false, 32);
        let encoded = zstd_encode_all(Cursor::new(b"this body is intentionally too large"), 0).unwrap();

        let err = stage
            .decode_zstd(&encoded)
            .expect_err("oversized zstd body should fail");

        assert!(err.to_string().contains("decompressed HTML response body exceeds configured limit"));
    }
}

#[async_trait]
impl FlowStage for JsInjectionStage {

    async fn on_response_body(&self, flow: &mut Flow) -> Result<()> {
        if self.inject_worker(flow)? { return Ok(()); }
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
