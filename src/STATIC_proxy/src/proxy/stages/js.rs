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
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use brotli::Decompressor;
use flate2::read::{GzDecoder, ZlibDecoder};
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use http::HeaderValue;
use sha2::{Digest, Sha256};
use std::{borrow::Cow, io::{Cursor, Read}};

use crate::{assets::ScriptBundle, proxy::flow::{Flow, ResponseParts}};

use super::FlowStage;

/// JS injector prepares the deterministic script payloads, decodes compressed HTML bodies,
/// records CSP hashes, and injects the STATIC bootstrap/globals/config/fingerprint bundles
/// directly into the `<head>` of every eligible document.
#[derive(Clone)]
pub struct JsInjectionStage {
    bundle: ScriptBundle,
    debug: bool,
}

impl JsInjectionStage {
    pub fn new(debug: bool) -> Self {
        Self {
            bundle: ScriptBundle::load(),
            debug,
        }
    }

    fn compute_hash(&self, script: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(script.as_bytes());
        let digest = hasher.finalize();
        STANDARD.encode(digest)
    }

    fn should_inject(&self, flow: &mut Flow) -> Result<bool> {
        let response = match flow.response.as_mut() {
            Some(resp) => resp,
            None => return Ok(false),
        };

        if !response.status.is_success() {
            return Ok(false);
        }

        if !Self::prepare_html_body(response)? {
            return Ok(false);
        }

        if response.body.is_empty() {
            return Ok(false);
        }

        if let Ok(body_str) = std::str::from_utf8(response.body.as_bytes()) {
            if body_str.contains("__404_bootstrap_version") {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        Ok(true)
    }

    fn render_config_layer(&self, flow: &Flow) -> String {
        let mut config_json = serde_json::to_string(&flow.metadata.fingerprint_config)
            .unwrap_or_else(|_| "{}".to_string());
        config_json = config_json.replace('\\', "\\\\");
        config_json = config_json.replace("</script>", "<\\/script>");

        self.bundle
            .config_layer
            .as_ref()
            .replace("{{config_json}}", &config_json)
    }

    fn build_injection_block(&self, flow: &Flow) -> (String, Vec<String>) {
        let config_layer = self.render_config_layer(flow);
        let segments: [Cow<'_, str>; 5] = [
            Cow::Borrowed(self.bundle.boot.as_ref()),
            Cow::Borrowed(self.bundle.shim.as_ref()),
            Cow::Owned(config_layer),
            Cow::Borrowed(self.bundle.spoofing.as_ref()),
            Cow::Borrowed(self.bundle.behavioral_noise.as_ref()),
        ];

        let mut hashes = Vec::with_capacity(segments.len());
        for segment in &segments {
            hashes.push(self.compute_hash(segment.as_ref()));
        }

        let nonce_attr = flow
            .metadata
            .csp_nonce
            .as_ref()
            .map(|nonce| format!(" nonce=\"{}\"", nonce))
            .unwrap_or_default();

        let mut block = String::with_capacity(segments.iter().map(|s| s.len()).sum::<usize>() + 128);
        for segment in segments {
            block.push_str("<script");
            block.push_str(&nonce_attr);
            block.push('>');
            block.push_str(segment.as_ref());
            block.push_str("</script>\n");
        }

        (block, hashes)
    }

    /// Confirms the response is HTML and decodes it into a plain buffer the injector can mutate.
    fn prepare_html_body(response: &mut ResponseParts) -> Result<bool> {
        let content_type = response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|raw| raw.to_ascii_lowercase())
            .unwrap_or_default();

        if !content_type.contains("text/html") {
            return Ok(false);
        }

        if !Self::ensure_plain_body(response)? {
            return Ok(false);
        }

        Ok(true)
    }

    fn ensure_plain_body(response: &mut ResponseParts) -> Result<bool> {
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
                "gzip" | "x-gzip" => Self::decode_gzip(&decoded)?,
                "deflate" => Self::decode_deflate(&decoded)?,
                "br" => Self::decode_brotli(&decoded)?,
                other => {
                    tracing::debug!(encoding = %other, "js_injector: unsupported content-encoding");
                    return Ok(false);
                }
            };
        }

        response.body.replace(&decoded);
        response.headers.remove(CONTENT_ENCODING);
        response.headers.remove(TRANSFER_ENCODING);
        let len_value = HeaderValue::from_str(&response.body.len().to_string())
            .context("invalid content-length after body decode")?;
        response.headers.insert(CONTENT_LENGTH, len_value);
        Ok(true)
    }

    fn decode_gzip(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    }

    fn decode_deflate(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    }

    fn decode_brotli(data: &[u8]) -> Result<Vec<u8>> {
        let cursor = Cursor::new(data);
        let mut decoder = Decompressor::new(cursor, 4096);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
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
}

enum InsertionStrategy {
    InsideHead(usize),
    CreateHeadAt(usize),
    PrependHead,
}

#[async_trait]
impl FlowStage for JsInjectionStage {
    /// Ensures the fingerprinting configuration is ready before bodies are sent.
    ///
    /// This stage runs after the upstream response body is buffered and just before
    /// we hand the HTML back to the client. It calculates CSP-compatible hashes for
    /// every injected script so the CSP stage can include them later in the response.
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

        let (injection_block, hashes) = self.build_injection_block(flow);

        let response = flow
            .response
            .as_mut()
            .expect("response checked in should_inject");

        let body = body_owned;
        let body_lower = body.to_ascii_lowercase();
        let strategy = self.choose_insertion_strategy(&body_lower);
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
            InsertionStrategy::PrependHead => {
                mutated.push_str(&wrapped_block);
                mutated.push_str(&body);
            }
        }

        response.body.replace(mutated.as_bytes());
        flow.metadata.script_hashes = hashes;

        if self.debug {
            tracing::debug!(%flow.id, "js_injection_applied" = true, bytes_added = injection_block.len());
        }

        Ok(())
    }
}
