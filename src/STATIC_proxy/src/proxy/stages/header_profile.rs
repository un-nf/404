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

use std::{collections::HashMap, fs, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue, USER_AGENT};
use parking_lot::RwLock;

use crate::proxy::flow::Flow;

use super::FlowStage;

/// HeaderProfileStage is the Rust equivalent of the Python HeaderProfile addon. It reads the
/// JSON profiles under `static_proxy/profiles/` once at startup, caches them in memory, and
/// annotates Flow metadata so downstream stages—especially JS injection—see deterministic
/// fingerprint data that matches the legacy pipeline.
#[derive(Clone)]
pub struct HeaderProfileStage {
    path: PathBuf,
    profiles: Arc<RwLock<HashMap<String, Arc<ProfileRecord>>>>,
    default_profile: String,
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
}

impl HeaderProfileStage {
    pub fn new(path: PathBuf, default_profile: String) -> Result<Self> {
        let stage = Self {
            path,
            profiles: Arc::new(RwLock::new(HashMap::new())),
            default_profile,
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
                let display = profile_display_name(&value, &key);
                let rules = HeaderProfileRules::from_value(&value);
                discovered.insert(
                    key,
                    Arc::new(ProfileRecord {
                        display_name: display,
                        config: value,
                        rules,
                    }),
                );
            }
            *self.profiles.write() = discovered;
            return Ok(());
        }

        let raw = fs::read_to_string(&self.path)
            .with_context(|| format!("failed to read profiles: {}", self.path.display()))?;

        // Support legacy aggregated profiles.json (with {"profiles": {...}})
        let value: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("invalid profiles JSON: {}", self.path.display()))?;

        if let Some(map) = value.get("profiles").and_then(|v| v.as_object()) {
            let mut parsed: HashMap<String, Arc<ProfileRecord>> = HashMap::new();
            for (k, v) in map {
                let display = profile_display_name(v, k);
                let rules = HeaderProfileRules::from_value(v);
                parsed.insert(
                    k.clone(),
                    Arc::new(ProfileRecord {
                        display_name: display,
                        config: v.clone(),
                        rules,
                    }),
                );
            }
            *self.profiles.write() = parsed;
        } else {
            let key = self
                .path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("profile")
                .to_string();
            let display = profile_display_name(&value, &key);
            let mut parsed = HashMap::new();
            let rules = HeaderProfileRules::from_value(&value);
            parsed.insert(
                key,
                Arc::new(ProfileRecord {
                    display_name: display,
                    config: value,
                    rules,
                }),
            );
            *self.profiles.write() = parsed;
        }
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
