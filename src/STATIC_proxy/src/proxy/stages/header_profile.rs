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

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue, ACCEPT, ACCEPT_ENCODING, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, USER_AGENT};
use parking_lot::RwLock;
use serde_json::{Map, Value};

use crate::proxy::flow::Flow;
use crate::tls::profiles::validate_profile_coherence;

use super::FlowStage;

/// HeaderProfileStage loads JSON profiles at startup, caches them in memory, and annotates
/// Flow metadata so downstream stages—especially JS injection—see deterministic
/// fingerprint data for each request.
#[derive(Clone)]
pub struct HeaderProfileStage {
    path: PathBuf,
    profiles: Arc<RwLock<HashMap<String, Arc<ProfileRecord>>>>,
    default_profile: String,
    startup_seed: u64,
}

struct ProfileRecord {
    display_name: String,
    config: serde_json::Value,
    rules: HeaderProfileRules,
}

#[derive(Clone, Default)]
struct HeaderProfileRules {
    remove: Vec<HeaderName>,
    replace: Vec<HeaderValueRule>,
    replace_arbitrary: Vec<HeaderValueRule>,
    replace_dynamic: Vec<DynamicRule>,
    set: Vec<HeaderValueRule>,
    append: Vec<HeaderValueRule>,
    _pass: Vec<HeaderName>,
    user_agent_hint: Option<String>,
}

#[derive(Clone)]
struct HeaderValueRule {
    name: HeaderName,
    value: String,
}

#[derive(Clone)]
struct DynamicRule {
    name: HeaderName,
    variants: HashMap<String, String>,
}

impl HeaderProfileRules {
    fn from_value(value: &serde_json::Value) -> Self {
        let mut rules = Self::default();
        rules.remove = parse_header_list(value.get("remove"));
        rules.replace = parse_pairs(value.get("replace"));
        rules.replace_arbitrary = parse_pairs(value.get("replaceArbitrary"));
        rules.replace_dynamic = parse_dynamic_rules(value.get("replaceDynamic"));
        rules.set = parse_pairs(value.get("set"));
        rules.append = parse_pairs(value.get("append"));
        rules._pass = parse_header_list(value.get("pass"));
        rules.compute_user_agent_hint();
        rules
    }

    fn compute_user_agent_hint(&mut self) {
        if self.user_agent_hint.is_none() {
            if let Some(rule) = self
                .replace
                .iter()
                .chain(self.set.iter())
                .find(|rule| rule.name == USER_AGENT)
            {
                self.user_agent_hint = Some(rule.value.clone());
            }
        }
    }
}

fn parse_header_list(value: Option<&serde_json::Value>) -> Vec<HeaderName> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str())
                .filter_map(|name| HeaderName::from_str(name).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_pairs(value: Option<&serde_json::Value>) -> Vec<HeaderValueRule> {
    let mut rules = Vec::new();
    let Some(raw) = value.and_then(|v| v.as_array()) else {
        return rules;
    };

    if raw.iter().all(|v| v.is_array()) {
        for entry in raw.iter().filter_map(|v| v.as_array()) {
            if entry.len() < 2 {
                continue;
            }
            if let Some(name) = entry[0].as_str() {
                if let Ok(header) = HeaderName::from_str(name) {
                    rules.push(HeaderValueRule {
                        name: header,
                        value: value_to_string(&entry[1]),
                    });
                }
            }
        }
        return rules;
    }

    let mut iter = raw.iter();
    while let Some(name) = iter.next() {
        let Some(value) = iter.next() else { break };
        if let Some(name_str) = name.as_str() {
            if let Ok(header) = HeaderName::from_str(name_str) {
                rules.push(HeaderValueRule {
                    name: header,
                    value: value_to_string(value),
                });
            }
        }
    }
    rules
}

fn parse_dynamic_rules(value: Option<&serde_json::Value>) -> Vec<DynamicRule> {
    let mut out = Vec::new();
    let Some(entries) = value.and_then(|v| v.as_array()) else {
        return out;
    };
    for entry in entries.iter().filter_map(|v| v.as_array()) {
        if entry.len() < 2 {
            continue;
        }
        let Some(name_str) = entry[0].as_str() else { continue };
        let Ok(name) = HeaderName::from_str(name_str) else { continue };
        let Some(map) = entry[1].as_object() else { continue };

        let mut variants = HashMap::new();
        for (key, value) in map {
            let normalized_key = unescape_value(key).to_ascii_lowercase();
            variants.insert(normalized_key, value_to_string(value));
        }
        out.push(DynamicRule { name, variants });
    }
    out
}

fn value_to_string(value: &serde_json::Value) -> String {
    let raw = match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    unescape_value(&raw)
}

fn unescape_value(input: &str) -> String {
    input.replace("\\*", "*")
}

fn apply_profile_rules(flow: &mut Flow, rules: &HeaderProfileRules) -> Result<()> {
    strip_proxy_sensitive_cache_validators(flow);
    normalize_html_navigation_accept_encoding(flow)?;

    let headers = &mut flow.request.headers;
    let request_path = flow.request.uri.path().to_string();

    for name in &rules.remove {
        headers.remove(name);
    }

    for rule in &rules.replace {
        if headers.contains_key(&rule.name) {
            let value = header_value(&rule.name, &rule.value)?;
            headers.insert(rule.name.clone(), value);
        }
    }

    for rule in &rules.replace_arbitrary {
        if headers.contains_key(&rule.name) {
            let value = header_value(&rule.name, &rule.value)?;
            headers.insert(rule.name.clone(), value);
        }
    }

    for dynamic in &rules.replace_dynamic {
        if let Some(existing) = headers.get(&dynamic.name) {
            if let Ok(current) = existing.to_str() {
                if let Some(next) = compute_dynamic_replacement(&request_path, current, dynamic) {
                    if next != current {
                        let value = header_value(&dynamic.name, &next)?;
                        headers.insert(dynamic.name.clone(), value);
                    }
                }
            }
        }
    }

    for rule in &rules.set {
        if !headers.contains_key(&rule.name) {
            let value = header_value(&rule.name, &rule.value)?;
            headers.insert(rule.name.clone(), value);
        }
    }

    for rule in &rules.append {
        let value = header_value(&rule.name, &rule.value)?;
        headers.append(rule.name.clone(), value);
    }

    Ok(())
}

fn strip_proxy_sensitive_cache_validators(flow: &mut Flow) {
    if !is_html_navigation_request(flow) && !is_bootstrap_asset_request(flow) {
        return;
    }

    flow.request.headers.remove(IF_NONE_MATCH);
    flow.request.headers.remove(IF_MODIFIED_SINCE);
    flow.request.headers.remove(IF_RANGE);
}

fn normalize_html_navigation_accept_encoding(flow: &mut Flow) -> Result<()> {
    if !is_html_navigation_request(flow) {
        return Ok(());
    }

    let Some(raw) = flow.request.headers.get(ACCEPT_ENCODING) else {
        return Ok(());
    };

    let Some(normalized) = normalize_accept_encoding_value(raw.to_str().unwrap_or_default()) else {
        flow.request.headers.remove(ACCEPT_ENCODING);
        return Ok(());
    };

    let value = HeaderValue::from_str(&normalized)
        .context("invalid Accept-Encoding value after HTML normalization")?;
    flow.request.headers.insert(ACCEPT_ENCODING, value);
    Ok(())
}

fn normalize_accept_encoding_value(raw: &str) -> Option<String> {
    let filtered: Vec<String> = raw
        .split(',')
        .filter_map(|token| {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                return None;
            }

            let encoding = trimmed
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();

            if encoding == "zstd" {
                return None;
            }

            Some(trimmed.to_string())
        })
        .collect();

    if filtered.is_empty() {
        None
    } else {
        Some(filtered.join(", "))
    }
}

fn is_html_navigation_request(flow: &Flow) -> bool {
    if flow.request.method != http::Method::GET && flow.request.method != http::Method::HEAD {
        return false;
    }

    let accept_is_html = flow
        .request
        .headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let lower = value.to_ascii_lowercase();
            lower.contains("text/html") || lower.contains("application/xhtml+xml")
        })
        .unwrap_or(false);

    if !accept_is_html {
        return false;
    }

    let fetch_mode = flow
        .request
        .headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("navigate"));

    let fetch_dest = flow
        .request
        .headers
        .get("sec-fetch-dest")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("document") || value.eq_ignore_ascii_case("iframe"));

    match (fetch_mode, fetch_dest) {
        (Some(true), Some(true)) => true,
        (Some(true), None) => true,
        (None, Some(true)) => true,
        (None, None) => true,
        _ => false,
    }
}

fn is_bootstrap_asset_request(flow: &Flow) -> bool {
    if flow.request.method != http::Method::GET && flow.request.method != http::Method::HEAD {
        return false;
    }

    if flow
        .request
        .headers
        .get("sec-fetch-dest")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.eq_ignore_ascii_case("script")
                || value.eq_ignore_ascii_case("worker")
                || value.eq_ignore_ascii_case("sharedworker")
                || value.eq_ignore_ascii_case("serviceworker")
        })
        .unwrap_or(false)
    {
        return true;
    }

    let path = flow.request.uri.path().to_ascii_lowercase();
    path.ends_with(".js") || path.ends_with(".mjs") || path.ends_with(".map")
}

fn header_value(name: &HeaderName, value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value).with_context(|| format!("invalid value for header {}", name))
}

fn compute_dynamic_replacement(path: &str, original: &str, rule: &DynamicRule) -> Option<String> {
    let accept_lower = original.to_ascii_lowercase();

    if let Some(kind) = detect_content_type(path, &accept_lower) {
        if kind == "xhr" {
            return None;
        }
        for key in content_type_candidates(kind) {
            if let Some(value) = rule.variants.get(*key) {
                return Some(value.clone());
            }
        }
    }

    if let Some(value) = accept_pattern_match(&rule.variants, &accept_lower) {
        return Some(value);
    }

    if accept_lower.contains("text/html") || original.trim() == "*/*" {
        if let Some(value) = rule.variants.get("default") {
            return Some(value.clone());
        }
    }

    None
}

fn detect_content_type(path: &str, accept_lower: &str) -> Option<&'static str> {
    let path_lower = path.to_ascii_lowercase();
    if ends_with_any(&path_lower, &[".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".avif"]) {
        return Some("image");
    }
    if path_lower.ends_with(".css") {
        return Some("css");
    }
    if path_lower.ends_with(".json") || accept_lower.contains("json") {
        return Some("json");
    }
    if path_lower.ends_with(".js") {
        return Some("javascript");
    }
    if ends_with_any(&path_lower, &[".woff", ".woff2", ".ttf", ".eot", ".otf"]) {
        return Some("font");
    }
    if path_lower.ends_with(".xml") {
        return Some("xml");
    }

    let trimmed = accept_lower.trim();
    let is_html_path = path_lower.ends_with(".html") || path_lower.ends_with(".htm");
    if trimmed == "*/*" && !is_html_path {
        return Some("xhr");
    }
    if !accept_lower.contains("text/html") && !accept_lower.contains("application/xhtml") {
        return Some("xhr");
    }

    None
}

fn content_type_candidates(kind: &str) -> &'static [&'static str] {
    match kind {
        "image" => &["image/", "image"],
        "css" => &["text/css", "css"],
        "json" => &["application/json", "json"],
        "javascript" => &["application/javascript", "text/javascript", "javascript"],
        "font" => &["application/font", "application/font-woff2", "application/font-woff", "font"],
        "xml" => &["application/xml", "text/xml", "xml"],
        _ => &[],
    }
}

fn accept_pattern_match(variants: &HashMap<String, String>, accept_lower: &str) -> Option<String> {
    let trimmed = accept_lower.trim();
    if trimmed == "*/*" {
        if let Some(value) = variants.get("*/*") {
            return Some(value.clone());
        }
    }

    for (pattern, value) in variants {
        if pattern == "default" || pattern == "*/*" {
            continue;
        }
        if accept_lower.contains(pattern) {
            return Some(value.clone());
        }
    }
    None
}

fn ends_with_any(path: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suffix| path.ends_with(suffix))
}

fn materialize_profile_config(base: &Value, profile_key: &str, startup_seed: u64) -> Value {
    let Some(overlays) = base.get("seeded_overlays").and_then(Value::as_object) else {
        return base.clone();
    };

    let mut materialized = base.clone();
    let mut selected_overlays = Map::new();

    for (category, entries_value) in overlays {
        let Some(entries) = entries_value.as_array() else {
            continue;
        };
        let Some(entry) = select_overlay_entry(entries, startup_seed, profile_key, category) else {
            continue;
        };

        if let Some(id) = overlay_entry_id(entry) {
            selected_overlays.insert(category.clone(), Value::String(id.to_string()));
        }

        apply_overlay_entry(&mut materialized, entry);
    }

    if let Some(object) = materialized.as_object_mut() {
        object.remove("seeded_overlays");
        if !selected_overlays.is_empty() {
            object.insert("selected_overlays".to_string(), Value::Object(selected_overlays));
        }
    }

    materialized
}

fn select_overlay_entry<'a>(
    entries: &'a [Value],
    startup_seed: u64,
    profile_key: &str,
    category: &str,
) -> Option<&'a Map<String, Value>> {
    let total_weight: f64 = entries
        .iter()
        .filter_map(Value::as_object)
        .map(overlay_entry_weight)
        .filter(|weight| *weight > 0.0)
        .sum();

    if total_weight <= 0.0 {
        return None;
    }

    let target = deterministic_choice_fraction(startup_seed, profile_key, category) * total_weight;
    let mut cursor = 0.0;
    let mut fallback = None;

    for entry in entries.iter().filter_map(Value::as_object) {
        let weight = overlay_entry_weight(entry);
        if weight <= 0.0 {
            continue;
        }

        cursor += weight;
        fallback = Some(entry);
        if target < cursor {
            return Some(entry);
        }
    }

    fallback
}

fn overlay_entry_weight(entry: &Map<String, Value>) -> f64 {
    entry
        .get("weight")
        .and_then(Value::as_f64)
        .filter(|weight| *weight > 0.0)
        .unwrap_or(1.0)
}

fn overlay_entry_id(entry: &Map<String, Value>) -> Option<&str> {
    entry.get("id").and_then(Value::as_str)
}

fn deterministic_choice_fraction(startup_seed: u64, profile_key: &str, category: &str) -> f64 {
    let mut hasher = DefaultHasher::new();
    startup_seed.hash(&mut hasher);
    profile_key.hash(&mut hasher);
    category.hash(&mut hasher);
    let hash = hasher.finish();

    (hash as f64) / ((u64::MAX as f64) + 1.0)
}

fn apply_overlay_entry(materialized: &mut Value, entry: &Map<String, Value>) {
    let Some(root) = materialized.as_object_mut() else {
        return;
    };

    if let Some(fingerprint_patch) = entry.get("fingerprint") {
        merge_value_at_key(root, "fingerprint", fingerprint_patch);
    }

    if let Some(headers_patch) = entry.get("headers").and_then(Value::as_object) {
        for (key, value) in headers_patch {
            merge_value_at_key(root, key, value);
        }
    }
}

fn merge_value_at_key(target: &mut Map<String, Value>, key: &str, patch: &Value) {
    if let Some(existing) = target.get_mut(key) {
        deep_merge_value(existing, patch);
    } else {
        target.insert(key.to_string(), patch.clone());
    }
}

fn deep_merge_value(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(target_object), Value::Object(patch_object)) => {
            for (key, value) in patch_object {
                if let Some(existing) = target_object.get_mut(key) {
                    deep_merge_value(existing, value);
                } else {
                    target_object.insert(key.clone(), value.clone());
                }
            }
        }
        (target_value, patch_value) => *target_value = patch_value.clone(),
    }
}

fn generate_startup_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| (duration.as_nanos() as u64) ^ (std::process::id() as u64))
        .unwrap_or_else(|_| std::process::id() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::flow::{BodyBuffer, RequestParts};
    use http::{HeaderMap, Method, Uri, Version};

    fn build_flow(path: &str) -> Flow {
        let request = RequestParts {
            method: Method::GET,
            uri: Uri::from_str(path).expect("valid uri"),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: BodyBuffer::default(),
        };
        Flow::new(request)
    }

    #[test]
    fn apply_rules_sets_and_removes_headers() {
        let config = serde_json::json!({
            "replace": [["User-Agent", "spoofed UA"]],
            "remove": ["Sec-CH-UA"],
            "set": [["Viewport-Width", "1920"]]
        });
        let rules = HeaderProfileRules::from_value(&config);
        let mut flow = build_flow("https://example.com/");
        flow.request
            .headers
            .insert("User-Agent", HeaderValue::from_static("original"));
        flow.request
            .headers
            .insert("Sec-CH-UA", HeaderValue::from_static("fake"));

        apply_profile_rules(&mut flow, &rules).expect("apply rules");

        assert_eq!(
            flow.request
                .headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok()),
            Some("spoofed UA")
        );
        assert!(flow.request.headers.get("sec-ch-ua").is_none());
        assert_eq!(
            flow.request
                .headers
                .get("viewport-width")
                .and_then(|h| h.to_str().ok()),
            Some("1920")
        );
    }

    #[test]
    fn replace_dynamic_updates_accept_header() {
        let config = serde_json::json!({
            "replaceDynamic": [
                [
                    "Accept",
                    {
                        "image/": "image/avif,image/webp,image/png",
                        "default": "text/html,application/xhtml+xml"
                    }
                ]
            ]
        });
        let rules = HeaderProfileRules::from_value(&config);
        let mut flow = build_flow("https://example.com/assets/logo.png");
        flow.request.headers.insert(
            "Accept",
            HeaderValue::from_static("image/avif,image/webp"),
        );

        apply_profile_rules(&mut flow, &rules).expect("apply dynamic rule");

        assert_eq!(
            flow.request
                .headers
                .get("accept")
                .and_then(|h| h.to_str().ok()),
            Some("image/avif,image/webp,image/png")
        );
    }

    #[test]
    fn strips_cache_validators_for_html_navigation_requests() {
        let rules = HeaderProfileRules::default();
        let mut flow = build_flow("https://example.com/");
        flow.request.headers.insert(
            ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        );
        flow.request
            .headers
            .insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        flow.request
            .headers
            .insert("sec-fetch-dest", HeaderValue::from_static("document"));
        flow.request
            .headers
            .insert(IF_NONE_MATCH, HeaderValue::from_static("\"etag\""));
        flow.request
            .headers
            .insert(IF_MODIFIED_SINCE, HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"));
        flow.request
            .headers
            .insert(IF_RANGE, HeaderValue::from_static("\"etag\""));

        apply_profile_rules(&mut flow, &rules).expect("apply rules");

        assert!(flow.request.headers.get(IF_NONE_MATCH).is_none());
        assert!(flow.request.headers.get(IF_MODIFIED_SINCE).is_none());
        assert!(flow.request.headers.get(IF_RANGE).is_none());
    }

    #[test]
    fn preserves_cache_validators_for_non_html_requests() {
        let rules = HeaderProfileRules::default();
        let mut flow = build_flow("https://example.com/api/data.json");
        flow.request
            .headers
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        flow.request
            .headers
            .insert(IF_NONE_MATCH, HeaderValue::from_static("\"etag\""));
        flow.request
            .headers
            .insert(IF_MODIFIED_SINCE, HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"));
        flow.request
            .headers
            .insert(IF_RANGE, HeaderValue::from_static("\"etag\""));

        apply_profile_rules(&mut flow, &rules).expect("apply rules");

        assert!(flow.request.headers.get(IF_NONE_MATCH).is_some());
        assert!(flow.request.headers.get(IF_MODIFIED_SINCE).is_some());
        assert!(flow.request.headers.get(IF_RANGE).is_some());
    }

    #[test]
    fn strips_cache_validators_for_script_bootstrap_requests() {
        let rules = HeaderProfileRules::default();
        let mut flow = build_flow("https://example.com/main-PNxJtFaN.js");
        flow.request
            .headers
            .insert(ACCEPT, HeaderValue::from_static("*/*"));
        flow.request
            .headers
            .insert("sec-fetch-dest", HeaderValue::from_static("script"));
        flow.request
            .headers
            .insert(IF_NONE_MATCH, HeaderValue::from_static("\"etag\""));
        flow.request
            .headers
            .insert(IF_MODIFIED_SINCE, HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"));
        flow.request
            .headers
            .insert(IF_RANGE, HeaderValue::from_static("\"etag\""));

        apply_profile_rules(&mut flow, &rules).expect("apply rules");

        assert!(flow.request.headers.get(IF_NONE_MATCH).is_none());
        assert!(flow.request.headers.get(IF_MODIFIED_SINCE).is_none());
        assert!(flow.request.headers.get(IF_RANGE).is_none());
    }

    #[test]
    fn preserves_cache_validators_for_non_bootstrap_xhr_requests() {
        let rules = HeaderProfileRules::default();
        let mut flow = build_flow("https://example.com/rest/model");
        flow.request
            .headers
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        flow.request
            .headers
            .insert("sec-fetch-dest", HeaderValue::from_static("empty"));
        flow.request
            .headers
            .insert(IF_NONE_MATCH, HeaderValue::from_static("\"etag\""));
        flow.request
            .headers
            .insert(IF_MODIFIED_SINCE, HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"));
        flow.request
            .headers
            .insert(IF_RANGE, HeaderValue::from_static("\"etag\""));

        apply_profile_rules(&mut flow, &rules).expect("apply rules");

        assert!(flow.request.headers.get(IF_NONE_MATCH).is_some());
        assert!(flow.request.headers.get(IF_MODIFIED_SINCE).is_some());
        assert!(flow.request.headers.get(IF_RANGE).is_some());
    }

    #[test]
    fn strips_zstd_from_html_navigation_accept_encoding() {
        let rules = HeaderProfileRules::default();
        let mut flow = build_flow("https://example.com/");
        flow.request.headers.insert(
            ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        );
        flow.request.headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        flow.request
            .headers
            .insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        flow.request
            .headers
            .insert("sec-fetch-dest", HeaderValue::from_static("document"));

        apply_profile_rules(&mut flow, &rules).expect("apply rules");

        assert_eq!(
            flow.request
                .headers
                .get(ACCEPT_ENCODING)
                .and_then(|h| h.to_str().ok()),
            Some("gzip, deflate, br")
        );
    }

    #[test]
    fn preserves_zstd_for_non_html_requests() {
        let rules = HeaderProfileRules::default();
        let mut flow = build_flow("https://example.com/app.js");
        flow.request
            .headers
            .insert(ACCEPT, HeaderValue::from_static("*/*"));
        flow.request.headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );

        apply_profile_rules(&mut flow, &rules).expect("apply rules");

        assert_eq!(
            flow.request
                .headers
                .get(ACCEPT_ENCODING)
                .and_then(|h| h.to_str().ok()),
            Some("gzip, deflate, br, zstd")
        );
    }

    #[test]
    fn materialized_profile_is_deterministic_for_same_seed() {
        let config = serde_json::json!({
            "fingerprint": {
                "name": "Example",
                "hardware_concurrency": 8
            },
            "seeded_overlays": {
                "hardware_profiles": [
                    {
                        "id": "desktop_a",
                        "weight": 1,
                        "fingerprint": {
                            "hardware_concurrency": 4,
                            "max_touch_points": 0
                        }
                    },
                    {
                        "id": "desktop_b",
                        "weight": 1,
                        "fingerprint": {
                            "hardware_concurrency": 8,
                            "max_touch_points": 5
                        }
                    }
                ]
            }
        });

        let first = materialize_profile_config(&config, "example", 7);
        let second = materialize_profile_config(&config, "example", 7);

        assert_eq!(first, second);
    }

    #[test]
    fn materialized_profile_varies_across_seeds() {
        let config = serde_json::json!({
            "fingerprint": {
                "name": "Example"
            },
            "seeded_overlays": {
                "hardware_profiles": [
                    {
                        "id": "desktop_a",
                        "weight": 1,
                        "fingerprint": {
                            "hardware_concurrency": 4
                        }
                    },
                    {
                        "id": "desktop_b",
                        "weight": 1,
                        "fingerprint": {
                            "hardware_concurrency": 8
                        }
                    }
                ]
            }
        });

        let first = materialize_profile_config(&config, "example", 0);
        let first_id = first
            .get("selected_overlays")
            .and_then(|value| value.get("hardware_profiles"))
            .and_then(Value::as_str)
            .expect("selected overlay id");

        let different = (1_u64..128)
            .map(|seed| materialize_profile_config(&config, "example", seed))
            .find(|value| {
                value
                    .get("selected_overlays")
                    .and_then(|entry| entry.get("hardware_profiles"))
                    .and_then(Value::as_str)
                    .map(|id| id != first_id)
                    .unwrap_or(false)
            })
            .expect("different seed selects a different overlay");

        assert_ne!(first, different);
    }

    #[test]
    fn build_js_runtime_uses_materialized_profile_without_overlay_pool() {
        let config = serde_json::json!({
            "fingerprint": {
                "name": "Example",
                "hardware_concurrency": 8
            },
            "seeded_overlays": {
                "hardware_profiles": [
                    {
                        "id": "desktop_a",
                        "weight": 1,
                        "fingerprint": {
                            "hardware_concurrency": 16,
                            "max_touch_points": 0
                        }
                    }
                ]
            }
        });

        let materialized = materialize_profile_config(&config, "example", 12);
        let runtime = build_js_runtime_config(&materialized);

        assert!(materialized.get("seeded_overlays").is_none());
        assert_eq!(
            runtime
                .get("fingerprint")
                .and_then(|value| value.get("hardware_concurrency"))
                .and_then(Value::as_i64),
            Some(16)
        );
        assert_eq!(
            runtime
                .get("fingerprint")
                .and_then(|value| value.get("max_touch_points"))
                .and_then(Value::as_i64),
            Some(0)
        );
    }

    #[test]
    fn header_rules_are_built_from_materialized_overlay() {
        let config = serde_json::json!({
            "set": [],
            "fingerprint": {
                "name": "Example"
            },
            "seeded_overlays": {
                "screen_profiles": [
                    {
                        "id": "screen_a",
                        "weight": 1,
                        "headers": {
                            "set": [["X-Overlay-Screen", "screen_a"]]
                        }
                    }
                ]
            }
        });

        let materialized = materialize_profile_config(&config, "example", 1);
        let rules = HeaderProfileRules::from_value(&materialized);
        let mut flow = build_flow("https://example.com/");

        apply_profile_rules(&mut flow, &rules).expect("apply rules");

        assert_eq!(
            flow.request
                .headers
                .get("x-overlay-screen")
                .and_then(|h| h.to_str().ok()),
            Some("screen_a")
        );
    }
}

impl HeaderProfileStage {
    pub fn new(path: PathBuf, default_profile: String) -> Result<Self> {
        let stage = Self {
            path,
            profiles: Arc::new(RwLock::new(HashMap::new())),
            default_profile,
            startup_seed: generate_startup_seed(),
        };
        stage.reload()?;
        Ok(stage)
    }

    /// Reloads the profiles JSON from disk. This is called during initialization.
    fn reload(&self) -> Result<()> {
        if self.path.is_dir() {
            let mut discovered: HashMap<String, Arc<ProfileRecord>> = HashMap::new();
            for entry in fs::read_dir(&self.path)
                .with_context(|| format!("failed to read profiles dir: {}", self.path.display()))?
            {
                let entry = entry?;
                if !entry.path().is_file() {
                    continue;
                }
                if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let raw = fs::read_to_string(entry.path())?;
                let value: serde_json::Value = serde_json::from_str(&raw)
                    .with_context(|| format!("invalid profile JSON: {}", entry.path().display()))?;
                let key = entry
                    .path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("profile")
                    .to_string();
                let materialized = materialize_profile_config(&value, &key, self.startup_seed);
                let display = profile_display_name(&materialized, &key);
                let rules = HeaderProfileRules::from_value(&materialized);
                log_profile_coherence_warnings(&key, &display, &materialized);
                discovered.insert(
                    key,
                    Arc::new(ProfileRecord {
                        display_name: display,
                        config: materialized,
                        rules,
                    }),
                );
            }
            *self.profiles.write() = discovered;
            return Ok(());
        }

        let raw = fs::read_to_string(&self.path)
            .with_context(|| format!("failed to read profiles: {}", self.path.display()))?;

        let value: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("invalid profiles JSON: {}", self.path.display()))?;

        let key = self
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("profile")
            .to_string();
        let materialized = materialize_profile_config(&value, &key, self.startup_seed);
        let display = profile_display_name(&materialized, &key);
        let mut parsed = HashMap::new();
        let rules = HeaderProfileRules::from_value(&materialized);
        log_profile_coherence_warnings(&key, &display, &materialized);
        parsed.insert(
            key,
            Arc::new(ProfileRecord {
                display_name: display,
                config: materialized,
                rules,
            }),
        );
        *self.profiles.write() = parsed;
        Ok(())
    }

    /// Picks the right profile to apply for the current flow (placeholder: first entry).
    fn select_profile(&self) -> Option<(String, Arc<ProfileRecord>)> {
        let profiles = self.profiles.read();
        if profiles.is_empty() {
            return None;
        }
        if let Some(record) = profiles.get(&self.default_profile) {
            return Some((self.default_profile.clone(), Arc::clone(record)));
        }

        if let Some((k, r)) = profiles
            .iter()
            .find(|(_, rec)| rec.display_name.eq_ignore_ascii_case(&self.default_profile))
        {
            return Some((k.clone(), Arc::clone(r)));
        }

        profiles
            .iter()
            .next()
            .map(|(k, r)| (k.clone(), Arc::clone(r)))
    }
}

#[async_trait]
impl FlowStage for HeaderProfileStage {
    /// Annotates the flow with the selected fingerprint profile metadata.
    async fn on_request(&self, flow: &mut Flow) -> Result<()> {
        if let Some((key, record)) = self.select_profile() {
            let profile = record.as_ref();
            flow.metadata.profile_name = Some(profile.display_name.clone());
            flow.metadata.browser_profile = Some(key);
            flow.metadata.fingerprint_config = profile.config.clone();
            flow.metadata.js_runtime_config = build_js_runtime_config(&profile.config);

            apply_profile_rules(flow, &profile.rules)?;
            flow.metadata.user_agent = flow
                .request
                .headers
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(|s| s.to_string())
                .or_else(|| profile.rules.user_agent_hint.clone());
        }
        Ok(())
    }
}

fn profile_display_name(value: &serde_json::Value, fallback: &str) -> String {
    value
        .get("fingerprint")
        .and_then(|fp| fp.get("name"))
        .and_then(|name| name.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| fallback.to_string())
}

fn build_js_runtime_config(config: &Value) -> Value {
    let Some(fingerprint) = config.get("fingerprint") else {
        return config.clone();
    };

    let mut runtime = Map::new();
    runtime.insert("fingerprint".to_string(), fingerprint.clone());

    for key in ["privacy", "privacy_rules", "behavior", "behavioral_noise"] {
        if let Some(value) = config.get(key) {
            runtime.insert(key.to_string(), value.clone());
        }
    }

    Value::Object(runtime)
}

fn log_profile_coherence_warnings(key: &str, display_name: &str, value: &Value) {
    for warning in validate_profile_coherence(value) {
        tracing::warn!(profile = key, display_name, "{warning}");
    }
}
