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
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue, ACCEPT, ACCEPT_ENCODING, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, USER_AGENT};
use parking_lot::RwLock;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::proxy::flow::Flow;
use crate::tls::profiles::validate_profile_coherence;

use super::FlowStage;

/// HeaderProfileStage loads JSON profiles at startup, caches them in memory, and annotates
/// Flow metadata so downstream stages—especially JS injection—see deterministic
/// fingerprint data for each request.
#[derive(Clone)]
pub struct HeaderProfileStage {
    store: ProfileStore,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProfileCatalogEntry {
    pub key: String,
    pub display_name: String,
    pub family: String,
    pub variant: String,
    pub platform: String,
}

#[derive(Clone)]
pub struct ProfileStore {
    inner: Arc<ProfileStoreInner>,
}

struct ProfileStoreInner {
    path: PathBuf,
    profiles: RwLock<HashMap<String, Arc<ProfileRecord>>>,
    default_profile: Option<String>,
    selected_profile: RwLock<Option<String>>,
    startup_seed: u64,
}

#[derive(Debug, Clone)]
struct ProfileIdentity {
    family: String,
    variant: String,
    platform: String,
    selection_weight: f64,
}

struct ProfileRecord {
    display_name: String,
    identity: ProfileIdentity,
    config: serde_json::Value,
    rules: HeaderProfileRules,
}

impl ProfileStore {
    pub fn load(path: PathBuf, default_profile: Option<String>) -> Result<Self> {
        let store = Self {
            inner: Arc::new(ProfileStoreInner {
                path,
                profiles: RwLock::new(HashMap::new()),
                default_profile: normalize_profile_name(default_profile),
                selected_profile: RwLock::new(None),
                startup_seed: generate_startup_seed(),
            }),
        };
        store.reload()?;
        Ok(store)
    }

    pub fn catalog(&self) -> Vec<ProfileCatalogEntry> {
        let mut entries = self
            .inner
            .profiles
            .read()
            .iter()
            .map(|(key, record)| ProfileCatalogEntry {
                key: key.clone(),
                display_name: record.display_name.clone(),
                family: record.identity.family.clone(),
                variant: record.identity.variant.clone(),
                platform: record.identity.platform.clone(),
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.family
                .cmp(&right.family)
                .then(left.variant.cmp(&right.variant))
                .then(left.key.cmp(&right.key))
        });
        entries
    }

    pub fn active_profile(&self) -> Option<ProfileCatalogEntry> {
        let selected = self.inner.selected_profile.read().clone();
        selected
            .as_deref()
            .and_then(|value| self.resolve_catalog_entry(value))
            .or_else(|| {
                self.inner
                    .default_profile
                    .as_deref()
                    .and_then(|value| self.resolve_catalog_entry(value))
            })
    }

    pub fn select_profile(&self, requested: &str) -> Result<ProfileCatalogEntry> {
        let entry = self
            .resolve_catalog_entry(requested)
            .with_context(|| format!("unknown profile '{requested}'"))?;
        *self.inner.selected_profile.write() = Some(entry.key.clone());
        Ok(entry)
    }

    fn reload(&self) -> Result<()> {
        if self.inner.path.is_dir() {
            let mut discovered: HashMap<String, Arc<ProfileRecord>> = HashMap::new();
            for path in collect_profile_json_files(&self.inner.path)? {
                let raw = fs::read_to_string(&path)?;
                let value: serde_json::Value = serde_json::from_str(&raw)
                    .with_context(|| format!("invalid profile JSON: {}", path.display()))?;
                let key = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("profile")
                    .to_string();
                let materialized = materialize_profile_config(&value, &key, self.inner.startup_seed);
                let display = profile_display_name(&materialized, &key);
                let identity = profile_identity(&materialized, &key);
                let rules = HeaderProfileRules::from_value(&materialized);
                log_profile_coherence_warnings(&key, &display, &materialized);
                discovered.insert(
                    key,
                    Arc::new(ProfileRecord {
                        display_name: display,
                        identity,
                        config: materialized,
                        rules,
                    }),
                );
            }
            *self.inner.profiles.write() = discovered;
            return Ok(());
        }

        let raw = fs::read_to_string(&self.inner.path)
            .with_context(|| format!("failed to read profiles: {}", self.inner.path.display()))?;

        let value: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("invalid profiles JSON: {}", self.inner.path.display()))?;

        let key = self
            .inner
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("profile")
            .to_string();
        let materialized = materialize_profile_config(&value, &key, self.inner.startup_seed);
        let display = profile_display_name(&materialized, &key);
        let identity = profile_identity(&materialized, &key);
        let mut parsed = HashMap::new();
        let rules = HeaderProfileRules::from_value(&materialized);
        log_profile_coherence_warnings(&key, &display, &materialized);
        parsed.insert(
            key,
            Arc::new(ProfileRecord {
                display_name: display,
                identity,
                config: materialized,
                rules,
            }),
        );
        *self.inner.profiles.write() = parsed;
        Ok(())
    }

    fn select_record_for_flow(&self, flow: &Flow) -> Option<(String, Arc<ProfileRecord>)> {
        let selected = self.inner.selected_profile.read().clone();
        selected
            .as_deref()
            .and_then(|value| self.resolve_record(value))
            .or_else(|| {
                self.inner
                    .default_profile
                    .as_deref()
                    .and_then(|value| self.resolve_record(value))
            })
            .or_else(|| {
                detect_request_browser_family(flow)
                    .and_then(|family| self.select_family_record(family))
            })
    }

    fn resolve_catalog_entry(&self, requested: &str) -> Option<ProfileCatalogEntry> {
        self.resolve_record(requested)
            .map(|(key, record)| ProfileCatalogEntry {
                key,
                display_name: record.display_name.clone(),
                family: record.identity.family.clone(),
                variant: record.identity.variant.clone(),
                platform: record.identity.platform.clone(),
            })
    }

    fn resolve_record(&self, requested: &str) -> Option<(String, Arc<ProfileRecord>)> {
        let profiles = self.inner.profiles.read();
        if profiles.is_empty() {
            return None;
        }
        if let Some(record) = profiles.get(requested) {
            return Some((requested.to_string(), Arc::clone(record)));
        }

        profiles
            .iter()
            .find(|(_, record)| {
                record.display_name.eq_ignore_ascii_case(requested)
                    || record.identity.variant.eq_ignore_ascii_case(requested)
            })
            .map(|(key, record)| (key.clone(), Arc::clone(record)))
    }

    fn select_family_record(&self, family: &str) -> Option<(String, Arc<ProfileRecord>)> {
        let profiles = self.inner.profiles.read();
        let candidates = profiles
            .iter()
            .filter(|(_, record)| record.identity.family.eq_ignore_ascii_case(family))
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return None;
        }

        let total_weight: f64 = candidates
            .iter()
            .map(|(_, record)| record.identity.selection_weight.max(0.0))
            .sum();

        if total_weight <= f64::EPSILON {
            let (key, record) = candidates[0];
            return Some((key.clone(), Arc::clone(record)));
        }

        let target = deterministic_choice_fraction(self.inner.startup_seed, family, "profile-family") * total_weight;
        let mut cursor = 0.0;
        let mut fallback = None;

        for (key, record) in candidates {
            let weight = record.identity.selection_weight.max(0.0);
            if weight <= 0.0 {
                continue;
            }

            cursor += weight;
            fallback = Some((key.clone(), Arc::clone(record)));
            if target < cursor {
                return Some((key.clone(), Arc::clone(record)));
            }
        }

        fallback
    }

    fn startup_seed(&self) -> u64 {
        self.inner.startup_seed
    }
}

fn normalize_profile_name(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn collect_profile_json_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_profile_json_files_recursive(dir, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_profile_json_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read profiles dir: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_profile_json_files_recursive(&path, out)?;
            continue;
        }
        if is_runtime_profile_path(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_runtime_profile_path(path: &Path) -> bool {
    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
        return false;
    }

    !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("manifest.json"))
}

fn profile_identity(value: &Value, fallback_key: &str) -> ProfileIdentity {
    let identity = value.get("profile_identity").and_then(Value::as_object);
    let fingerprint = value.get("fingerprint").and_then(Value::as_object);
    let browser_type = fingerprint
        .and_then(|entry| entry.get("browser_type"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    let family = identity
        .and_then(|entry| entry.get("family"))
        .and_then(Value::as_str)
        .map(|entry| entry.to_ascii_lowercase())
        .or_else(|| {
            fingerprint
                .and_then(|entry| entry.get("browser_family"))
                .and_then(Value::as_str)
                .map(|entry| entry.to_ascii_lowercase())
        })
        .unwrap_or_else(|| derive_browser_family(browser_type));

    let variant = identity
        .and_then(|entry| entry.get("variant"))
        .and_then(Value::as_str)
        .map(|entry| entry.to_ascii_lowercase())
        .or_else(|| {
            fingerprint
                .and_then(|entry| entry.get("browser_variant"))
                .and_then(Value::as_str)
                .map(|entry| entry.to_ascii_lowercase())
        })
        .filter(|entry| !entry.is_empty())
        .unwrap_or_else(|| derive_profile_variant(browser_type, fallback_key));

    let platform = identity
        .and_then(|entry| entry.get("platform"))
        .and_then(Value::as_str)
        .map(|entry| entry.to_ascii_lowercase())
        .or_else(|| {
            fingerprint
                .and_then(|entry| entry.get("os"))
                .and_then(Value::as_str)
                .map(normalize_profile_platform)
        })
        .unwrap_or_else(|| "windows".to_string());

    let selection_weight = identity
        .and_then(|entry| entry.get("selection_weight"))
        .and_then(Value::as_f64)
        .filter(|entry| *entry > 0.0)
        .unwrap_or(1.0);

    ProfileIdentity {
        family,
        variant,
        platform,
        selection_weight,
    }
}

fn derive_browser_family(browser_type: &str) -> String {
    match browser_type.to_ascii_lowercase().as_str() {
        "firefox" | "gecko" | "tor" | "mullvad" => "firefox-like".to_string(),
        "chrome" | "chromium" | "edge" | "brave" | "vivaldi" | "opera" => "chromium-like".to_string(),
        _ => "chromium-like".to_string(),
    }
}

fn derive_profile_variant(browser_type: &str, fallback_key: &str) -> String {
    let browser_type = browser_type.trim().to_ascii_lowercase();
    if !browser_type.is_empty() {
        return browser_type;
    }

    fallback_key
        .split('-')
        .next()
        .unwrap_or("chrome")
        .to_ascii_lowercase()
}

fn normalize_profile_platform(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "windows" | "win32" | "win64" => "windows".to_string(),
        "macos" | "mac os" | "mac" | "macintel" => "macos".to_string(),
        "linux" | "x11" => "linux".to_string(),
        "android" => "android".to_string(),
        "ios" | "iphone" | "ipad" => "ios".to_string(),
        other => other.to_string(),
    }
}

fn detect_request_browser_family(flow: &Flow) -> Option<&'static str> {
    let sec_ch_ua = flow
        .request
        .headers
        .get("sec-ch-ua")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if sec_ch_ua.contains("firefox") {
        return Some("firefox-like");
    }

    if sec_ch_ua.contains("chromium") || sec_ch_ua.contains("google chrome") || sec_ch_ua.contains("microsoft edge") {
        return Some("chromium-like");
    }

    let user_agent = flow
        .request
        .headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if user_agent.contains("firefox/") {
        return Some("firefox-like");
    }

    if user_agent.contains("edg/") || user_agent.contains("chrome/") || user_agent.contains("chromium") {
        return Some("chromium-like");
    }

    None
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
    let mut random_seed = [0u8; 8];
    OsRng.fill_bytes(&mut random_seed);
    let os_seed = u64::from_le_bytes(random_seed);

    if os_seed != 0 {
        return os_seed;
    }

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
    use tempfile::tempdir;

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

    fn write_profile_fixture(
        dir: &std::path::Path,
        file_name: &str,
        display_name: &str,
        family: &str,
        variant: &str,
        browser_type: &str,
    ) {
        let profile = serde_json::json!({
            "profile_identity": {
                "family": family,
                "variant": variant,
                "platform": "windows",
                "selection_weight": 1.0
            },
            "fingerprint": {
                "name": display_name,
                "browser_type": browser_type,
                "browser_family": family,
                "browser_variant": variant,
                "user_agent": "Mozilla/5.0"
            }
        });

        fs::write(
            dir.join(file_name),
            serde_json::to_vec(&profile).expect("serialize profile"),
        )
        .expect("write profile fixture");
    }

    #[test]
    fn profile_store_catalog_uses_default_profile_as_active() {
        let dir = tempdir().expect("tempdir");
        write_profile_fixture(dir.path(), "firefox-windows.json", "Firefox Windows", "firefox-like", "firefox", "firefox");
        write_profile_fixture(dir.path(), "chrome-windows.json", "Chrome Windows", "chromium-like", "chrome", "chrome");

        let store = ProfileStore::load(dir.path().to_path_buf(), Some("firefox-windows".to_string()))
            .expect("load profile store");

        let catalog = store.catalog();
        assert_eq!(
            catalog.iter().map(|entry| entry.key.as_str()).collect::<Vec<_>>(),
            vec!["chrome-windows", "firefox-windows"]
        );
        assert_eq!(
            store.active_profile(),
            Some(ProfileCatalogEntry {
                key: "firefox-windows".to_string(),
                display_name: "Firefox Windows".to_string(),
                family: "firefox-like".to_string(),
                variant: "firefox".to_string(),
                platform: "windows".to_string(),
            })
        );
    }

    #[test]
    fn profile_store_ignores_manifest_metadata_file() {
        let dir = tempdir().expect("tempdir");
        write_profile_fixture(dir.path(), "firefox-windows.json", "Firefox Windows", "firefox-like", "firefox", "firefox");
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "profiles": [
                    {
                        "file_name": "firefox-windows.json",
                        "path": "/src/STATIC_proxy/profiles/firefox-windows.json",
                        "sha256": "deadbeef"
                    }
                ]
            }))
            .expect("serialize manifest fixture"),
        )
        .expect("write manifest fixture");

        let store = ProfileStore::load(dir.path().to_path_buf(), None)
            .expect("load profile store");

        assert_eq!(
            store.catalog(),
            vec![ProfileCatalogEntry {
                key: "firefox-windows".to_string(),
                display_name: "Firefox Windows".to_string(),
                family: "firefox-like".to_string(),
                variant: "firefox".to_string(),
                platform: "windows".to_string(),
            }]
        );
    }

    #[test]
    fn profile_store_selects_profile_by_display_name() {
        let dir = tempdir().expect("tempdir");
        write_profile_fixture(dir.path(), "firefox-windows.json", "Firefox Windows", "firefox-like", "firefox", "firefox");
        write_profile_fixture(dir.path(), "chrome-windows.json", "Chrome Windows", "chromium-like", "chrome", "chrome");

        let store = ProfileStore::load(dir.path().to_path_buf(), None)
            .expect("load profile store");

        let selected = store
            .select_profile("Chrome Windows")
            .expect("select by display name");

        assert_eq!(
            selected,
            ProfileCatalogEntry {
                key: "chrome-windows".to_string(),
                display_name: "Chrome Windows".to_string(),
                family: "chromium-like".to_string(),
                variant: "chrome".to_string(),
                platform: "windows".to_string(),
            }
        );
        assert_eq!(store.active_profile(), Some(selected));
    }

    #[test]
    fn profile_store_auto_selects_from_host_family() {
        let dir = tempdir().expect("tempdir");
        write_profile_fixture(dir.path(), "firefox-windows.json", "Firefox Windows", "firefox-like", "firefox", "firefox");
        write_profile_fixture(dir.path(), "chrome-windows.json", "Chrome Windows", "chromium-like", "chrome", "chrome");
        write_profile_fixture(dir.path(), "edge-windows.json", "Edge Windows", "chromium-like", "edge", "edge");

        let store = ProfileStore::load(dir.path().to_path_buf(), None)
            .expect("load profile store");
        let mut flow = build_flow("https://example.com/");
        flow.request.headers.insert(
            USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"),
        );
        flow.request.headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static("\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"147\", \"Google Chrome\";v=\"147\""),
        );

        let (_, record) = store
            .select_record_for_flow(&flow)
            .expect("family-selected profile");

        assert_eq!(record.identity.family, "chromium-like");
        assert!(record.identity.variant == "chrome" || record.identity.variant == "edge");
    }

    #[test]
    fn profile_store_prefers_explicit_profile_over_detected_family() {
        let dir = tempdir().expect("tempdir");
        write_profile_fixture(dir.path(), "firefox-windows.json", "Firefox Windows", "firefox-like", "firefox", "firefox");
        write_profile_fixture(dir.path(), "chrome-windows.json", "Chrome Windows", "chromium-like", "chrome", "chrome");

        let store = ProfileStore::load(dir.path().to_path_buf(), Some("firefox-windows".to_string()))
            .expect("load profile store");
        let mut flow = build_flow("https://example.com/");
        flow.request.headers.insert(
            USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"),
        );

        let (_, record) = store
            .select_record_for_flow(&flow)
            .expect("explicitly selected profile");

        assert_eq!(record.identity.family, "firefox-like");
        assert_eq!(record.identity.variant, "firefox");
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
        let runtime = build_js_runtime_config(&materialized, 12);

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
        Ok(Self {
            store: ProfileStore::load(path, Some(default_profile))?,
        })
    }

    pub fn from_store(store: ProfileStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl FlowStage for HeaderProfileStage {
    /// Annotates the flow with the selected fingerprint profile metadata.
    async fn on_request(&self, flow: &mut Flow) -> Result<()> {
        if let Some((key, record)) = self.store.select_record_for_flow(flow) {
            let profile = record.as_ref();
            flow.metadata.profile_name = Some(profile.display_name.clone());
            flow.metadata.browser_profile = Some(key);
            flow.metadata.fingerprint_config = profile.config.clone();
            flow.metadata.js_runtime_config = build_js_runtime_config(&profile.config, self.store.startup_seed());

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

fn build_js_runtime_config(config: &Value, startup_seed: u64) -> Value {
    let Some(fingerprint) = config.get("fingerprint") else {
        return config.clone();
    };

    let mut runtime = Map::new();
    let mut runtime_fingerprint = fingerprint.clone();
    if let (Some(profile_identity), Some(fingerprint_object)) = (
        config.get("profile_identity").and_then(Value::as_object),
        runtime_fingerprint.as_object_mut(),
    ) {
        if let Some(family) = profile_identity.get("family").and_then(Value::as_str) {
            fingerprint_object
                .entry("browser_family".to_string())
                .or_insert_with(|| Value::String(family.to_string()));
        }
        if let Some(variant) = profile_identity.get("variant").and_then(Value::as_str) {
            fingerprint_object
                .entry("browser_variant".to_string())
                .or_insert_with(|| Value::String(variant.to_string()));
        }
        if let Some(platform) = profile_identity.get("platform").and_then(Value::as_str) {
            fingerprint_object
                .entry("profile_platform".to_string())
                .or_insert_with(|| Value::String(platform.to_string()));
        }
    }
    runtime.insert("fingerprint".to_string(), runtime_fingerprint);
    runtime.insert(
        "startup_salt".to_string(),
        Value::String(format!("{startup_seed:016x}")),
    );

    if let Some(profile_identity) = config.get("profile_identity") {
        runtime.insert("profile_identity".to_string(), profile_identity.clone());
    }

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
