//! The same constrained JSON Schema contract is read by Rust and JavaScript.
use anyhow::{bail, Result};
use serde_json::Value;
use std::sync::OnceLock;

fn schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!("../schema/runtime-profile.schema.json"))
            .expect("runtime schema")
    })
}

pub fn resolve_audio_pool(profile: &mut Value, fraction: f64) -> Result<()> {
    let Some(pool) = profile["fingerprint"]["audio_context"]["hardware_profiles"]
        .as_array()
        .cloned()
    else {
        return Ok(());
    };
    if pool.is_empty() {
        bail!("STATIC empty audio hardware pool");
    }
    let rule = &schema()["properties"]["audio_context"]["properties"]["hardware_profiles"]["items"];
    for entry in &pool {
        validate(entry, rule, "audio hardware pool entry")?;
    }
    let weights = pool
        .iter()
        .map(|entry| entry["weight"].as_f64().unwrap_or(1.0))
        .collect::<Vec<_>>();
    let total: f64 = weights.iter().sum();
    if !total.is_finite() || total <= 0.0 {
        bail!("STATIC invalid audio pool weights");
    }
    let mut cursor = fraction * total;
    let mut last = None;
    for (entry, weight) in pool.iter().zip(weights) {
        if weight <= 0.0 {
            continue;
        }
        last = Some(entry);
        if cursor < weight {
            profile["fingerprint"]["audio_context"]["hardware_profiles"] =
                serde_json::json!([entry]);
            return Ok(());
        }
        cursor -= weight;
    }
    if let Some(entry) = last {
        profile["fingerprint"]["audio_context"]["hardware_profiles"] = serde_json::json!([entry]);
        return Ok(());
    }
    bail!("STATIC audio pool selection failed")
}

pub fn validate_fingerprint(value: &Value) -> Result<()> {
    if value
        .get("webrtc_observation_policy")
        .and_then(Value::as_str)
        == Some("preserve-relay-routing")
        && value.get("webrtc_transport_policy").and_then(Value::as_str) != Some("relay-only")
    {
        anyhow::bail!("STATIC relay routing observations require relay-only transport");
    }

    let canonical = canonical_fingerprint(value)?;
    let value = &canonical;
    validate(value, schema(), "fingerprint")?;
    validate_identity(value)?;
    let ua = value["user_agent"].as_str().unwrap_or("");
    let platform = value["platform"].as_str().unwrap_or("");
    if (ua.contains("Windows") && !platform.starts_with("Win"))
        || (ua.contains("Mac OS X") && platform != "MacIntel")
    {
        bail!("STATIC UA/platform contradiction");
    }
    let resolution = value["screen_resolution"].as_str().unwrap_or("1920x1080");
    let dimensions = resolution
        .split('x')
        .filter_map(|part| part.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if dimensions.len() == 2
        && (value["screen_avail_width"]
            .as_u64()
            .unwrap_or(dimensions[0])
            > dimensions[0]
            || value["screen_avail_height"]
                .as_u64()
                .unwrap_or(dimensions[1])
                > dimensions[1])
    {
        bail!("STATIC available screen exceeds screen dimensions");
    }
    if value["audio_context"]["channel_count"]
        .as_u64()
        .unwrap_or(0)
        > value["audio_context"]["max_channel_count"]
            .as_u64()
            .unwrap_or(32)
    {
        bail!("STATIC audio channels exceed destination maximum");
    }
    for axis in ["width", "height"] {
        if value["enable_viewport_spoof"] == true {
            if let (Some(inner), Some(outer)) = (
                value[format!("window_inner_{axis}")].as_u64(),
                value[format!("window_outer_{axis}")].as_u64(),
            ) {
                if inner > outer {
                    bail!("STATIC inner window exceeds outer dimensions");
                }
            }
        }
    }
    if let Some(pool) = value["audio_context"]["hardware_profiles"].as_array() {
        if pool.len() != 1 || pool[0]["weight"].as_f64() == Some(0.0) {
            bail!("STATIC audio hardware pool must be resolved once before delivery");
        }
    }
    if let Some(contexts) = value["webgl_contexts"].as_object() {
        let enums: Value = serde_json::from_str(include_str!("../schema/webgl-parameters.json"))
            .expect("WebGL enum contract");
        for (kind, record) in contexts {
            let mut aliases = std::collections::HashMap::<u64, &Value>::new();
            if let Some(parameters) = record["parameters"].as_object() {
                for (key, parameter) in parameters {
                    let rule = &enums[key];
                    if !rule["versions"].as_array().is_some_and(|versions| {
                        versions
                            .iter()
                            .any(|version| version.as_str() == Some(kind))
                    }) {
                        bail!("STATIC unresolved {kind} parameter {key}");
                    }
                    let number = rule["enum"].as_u64().expect("enum number");
                    if let Some(prior) = aliases.insert(number, parameter) {
                        if prior != parameter
                            && !prior
                                .as_f64()
                                .zip(parameter.as_f64())
                                .is_some_and(|(left, right)| left == right)
                        {
                            bail!("STATIC conflicting {kind} parameter aliases");
                        }
                    }
                    if let Some(array) = parameter.as_array() {
                        if array.len() != 2
                            || key != "MAX_VIEWPORT_DIMS" && array[0].as_f64() > array[1].as_f64()
                        {
                            bail!("STATIC invalid WebGL parameter shape {key}");
                        }
                        if key == "MAX_VIEWPORT_DIMS"
                            && array.iter().any(|n| {
                                n.as_f64()
                                    .is_none_or(|v| v < 0.0 || v.fract() != 0.0 || v > 2147483647.0)
                            })
                        {
                            bail!("STATIC invalid viewport Int32 values");
                        }
                    }
                }
            }
        }
    }
    let variants = ["browser_variant", "profile_variant", "browser_type"]
        .iter()
        .filter_map(|key| value.get(key).and_then(Value::as_str))
        .map(|text| text.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if variants.is_empty() {
        bail!("STATIC browser variant required");
    }
    if variants.iter().any(|variant| variant != &variants[0]) {
        bail!("STATIC conflicting browser variants");
    }
    if let Some(variant) = variants.first() {
        let family = schema()["x-variant-families"][variant].as_str();
        if family == Some("chromium-like") && value.get("ua_data").is_none() {
            bail!("STATIC chromium identity requires complete ua_data");
        }
        for key in ["browser_family", "profile_family"] {
            if value
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| Some(value) != family)
            {
                bail!("STATIC conflicting browser family");
            }
        }
    }
    for (key, rule) in schema()["properties"].as_object().expect("properties") {
        if let Some(alias) = rule["x-alias"].as_str() {
            if let (Some(left), Some(right)) = (value.get(key), value.get(alias)) {
                if left != right {
                    bail!("STATIC conflicting {key}/{alias}");
                }
            }
        }
    }
    Ok(())
}
fn version_major(value: &str) -> Result<u64> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.is_empty()
        || parts.len() > 4
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || part.parse::<u32>().is_err()
        })
    {
        bail!("STATIC invalid version");
    }
    Ok(parts[0].parse()?)
}
fn token_major(ua: &str, token: &str) -> Result<Option<u64>> {
    ua.split_once(token)
        .map(|(_, value)| version_major(value.split(' ').next().unwrap_or("")))
        .transpose()
}
fn validate_identity(value: &Value) -> Result<()> {
    let normalized = ["browser_variant", "profile_variant", "browser_type"]
        .iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let variant = normalized.as_str();
    let ua = value["user_agent"].as_str().unwrap_or("");
    let engine = token_major(ua, "Chrome/")?;
    let firefox = token_major(ua, "Firefox/")?;
    let edge = token_major(ua, "Edg/")?;
    let product = if variant == "edge" {
        edge
    } else if ["firefox", "librewolf", "waterfox"].contains(&variant) {
        firefox
    } else {
        engine
    };
    if [
        "chrome",
        "chromium",
        "edge",
        "firefox",
        "librewolf",
        "waterfox",
    ]
    .contains(&variant)
        && product.is_none()
    {
        bail!("STATIC UA does not identify the selected browser variant");
    }
    if let Some(version) = value["browser_version"].as_str() {
        if ["chrome", "chromium", "edge", "firefox"].contains(&variant)
            && Some(version_major(version)?) != product
        {
            bail!("STATIC browser version contradicts UA");
        }
    }
    let Some(data) = value.get("ua_data") else {
        return Ok(());
    };
    let platform = data["platform"].as_str().unwrap_or("");
    if !platform.is_empty()
        && ((ua.contains("Windows") && platform != "Windows")
            || (ua.contains("Mac OS X") && platform != "macOS"))
    {
        bail!("STATIC UA/client-hint platform contradiction");
    }
    let bits = data["bitness"].as_str().unwrap_or("");
    if data["wow64"] == true
        && ((!platform.is_empty() && platform != "Windows") || (!bits.is_empty() && bits != "64"))
    {
        bail!("STATIC WoW64 requires a 64-bit Windows platform");
    }
    if let Some(version) = data["ua_full_version"].as_str().filter(|v| !v.is_empty()) {
        if ["chrome", "chromium", "edge"].contains(&variant)
            && Some(version_major(version)?) != product
        {
            bail!("STATIC full version contradicts UA");
        }
    }
    for key in ["brands", "full_version_list"] {
        if let Some(rows) = data[key].as_array() {
            for row in rows {
                let major = version_major(row["version"].as_str().unwrap_or(""))?;
                let expected = match row["brand"].as_str() {
                    Some("Chromium" | "Google Chrome") => engine,
                    Some("Microsoft Edge") => edge,
                    _ => None,
                };
                if expected.is_some() && Some(major) != expected {
                    bail!("STATIC brand version contradicts UA");
                }
            }
        }
    }
    Ok(())
}

pub fn apply_defaults(value: &Value) -> Result<Value> {
    validate_fingerprint(value)?;
    let mut normalized = canonical_fingerprint(value)?;
    let object = normalized.as_object_mut().expect("validated object");
    for (key, rule) in schema()["properties"].as_object().expect("properties") {
        if let Some(alias) = rule["x-alias"].as_str() {
            if let Some(value) = object.get(key).cloned() {
                object.insert(alias.to_string(), value);
            }
        }
    }
    for (key, rule) in schema()["properties"].as_object().expect("properties") {
        if !object.contains_key(key) {
            if let Some(default) = rule.get("default") {
                object.insert(key.clone(), default.clone());
            }
        }
    }
    if normalized["storage_usage"].as_f64().unwrap_or(0.0)
        > normalized["storage_quota"].as_f64().unwrap_or(0.0)
    {
        bail!("STATIC storage usage exceeds quota");
    }
    Ok(normalized)
}

fn canonical_fingerprint(value: &Value) -> Result<Value> {
    let mut result = value.clone();
    if let Some(data) = result.get_mut("ua_data").and_then(Value::as_object_mut) {
        if let Some(alias) = data.get("formFactors").cloned() {
            if data
                .get("form_factors")
                .is_some_and(|current| current != &alias)
            {
                bail!("STATIC conflicting formFactors/form_factors");
            }
            data.insert("form_factors".into(), alias);
        }
    }
    Ok(result)
}

fn validate(value: &Value, rule: &Value, path: &str) -> Result<()> {
    if let Some(array) = value.as_array() {
        if array.len() < rule["minItems"].as_u64().unwrap_or(0) as usize
            || array.len() > rule["maxItems"].as_u64().unwrap_or(u64::MAX) as usize
        {
            bail!("STATIC {path}: invalid array length");
        }
    }
    if let Some(branches) = rule["anyOf"].as_array() {
        if !branches
            .iter()
            .any(|branch| validate(value, branch, path).is_ok())
        {
            bail!("STATIC {path}: no supported variant");
        }
    }
    let expected: Vec<&str> = match rule.get("type") {
        Some(Value::String(kind)) => vec![kind.as_str()],
        Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if !expected.is_empty()
        && !expected.iter().any(|kind| match *kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            "number" => value.is_number(),
            "integer" => value.as_f64().is_some_and(|number| {
                number.is_finite() && number.fract() == 0.0 && number.abs() <= 9007199254740991.0
            }),
            _ => false,
        })
    {
        bail!("STATIC {path}: invalid type");
    }
    if let Some(number) = value.as_f64() {
        if number < rule["minimum"].as_f64().unwrap_or(f64::NEG_INFINITY)
            || number > rule["maximum"].as_f64().unwrap_or(f64::INFINITY)
        {
            bail!("STATIC {path}: invalid range");
        }
    }
    if let Some(text) = value.as_str() {
        if rule["x-http-string"].as_bool() == Some(true)
            && !text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            bail!("STATIC {path}: invalid HTTP string");
        }
        if rule["x-resolution"].as_bool() == Some(true) {
            let parts = text.split('x').collect::<Vec<_>>();
            if parts.len() != 2
                || parts.iter().any(|part| {
                    part.is_empty()
                        || !part.bytes().all(|b| b.is_ascii_digit())
                        || part.parse::<u32>().map_or(true, |n| n == 0 || n > 131072)
                })
            {
                bail!("STATIC {path}: invalid resolution");
            }
        }
        if rule["x-nonempty"].as_bool().unwrap_or(false) && text.trim().is_empty() {
            bail!("STATIC {path}: empty string");
        }
        if text.chars().count() < rule["minLength"].as_u64().unwrap_or(0) as usize {
            bail!("STATIC {path}: empty string");
        }
    }
    if let Some(choices) = rule["enum"].as_array() {
        let folded;
        let compared = if rule["x-casefold"].as_bool().unwrap_or(false) && value.is_string() {
            folded = Value::String(value.as_str().unwrap().trim().to_ascii_lowercase());
            &folded
        } else {
            value
        };
        if !choices.iter().any(|choice| {
            choice == compared
                || choice
                    .as_f64()
                    .zip(compared.as_f64())
                    .is_some_and(|(left, right)| left == right)
        }) {
            bail!("STATIC {path}: invalid enum");
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(item_rule) = rule.get("items") {
            for (index, item) in items.iter().enumerate() {
                validate(item, item_rule, &format!("{path}[{index}]"))?;
            }
        }
    } else if let Some(object) = value.as_object() {
        if let Some(required) = rule["required"].as_array() {
            for key in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(key) {
                    bail!("STATIC {path}.{key}: required");
                }
            }
        }
        for (key, item) in object {
            let child = rule["properties"]
                .get(key)
                .or_else(|| rule.get("additionalProperties"));
            match child {
                Some(Value::Bool(false)) => bail!("STATIC {path}.{key}: unknown field"),
                Some(child) if child.is_object() => {
                    validate(item, child, &format!("{path}.{key}"))?
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn webgl_enum_aliases_and_version_ownership_validate_before_delivery() {
        let profile: Value =
            serde_json::from_str(include_str!("../profiles/chrome-windows.json")).unwrap();
        let mut fingerprint = profile["fingerprint"].clone();
        fingerprint["webgl_contexts"]["webgl2"]["parameters"]["MAX_DRAW_BUFFERS_WEBGL"] =
            serde_json::json!(7);
        assert!(apply_defaults(&fingerprint).is_err());
        fingerprint["webgl_contexts"]["webgl2"]["parameters"]["MAX_DRAW_BUFFERS_WEBGL"] =
            serde_json::json!(8.0);
        apply_defaults(&fingerprint).unwrap();
        fingerprint["webgl_contexts"]["webgl1"]["parameters"]["MAX_TEXTURE_LOD_BIAS"] =
            serde_json::json!(2);
        assert!(apply_defaults(&fingerprint).is_err());
    }
    #[test]
    fn audio_pool_resolves_once_and_rejects_invalid_candidates() {
        let mut profile = serde_json::json!({"fingerprint":{"audio_context":{"hardware_profiles":[{"id":"first","weight":1,"sample_rate":44100},{"id":"second","weight":3,"sample_rate":48000}]}}});
        resolve_audio_pool(&mut profile, 0.8).unwrap();
        assert_eq!(
            profile["fingerprint"]["audio_context"]["hardware_profiles"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            profile["fingerprint"]["audio_context"]["hardware_profiles"][0]["id"],
            "second"
        );
        let selected = profile.clone();
        resolve_audio_pool(&mut profile, 0.1).unwrap();
        assert_eq!(profile, selected);
        for invalid in [
            serde_json::json!([]),
            serde_json::json!([{"weight":0}]),
            serde_json::json!([{"sample_rate":0}]),
        ] {
            let mut profile =
                serde_json::json!({"fingerprint":{"audio_context":{"hardware_profiles":invalid}}});
            assert!(resolve_audio_pool(&mut profile, 0.5).is_err());
        }
    }
    #[test]
    fn shared_profile_acceptance_cases_match_js_contract() {
        let base: Value =
            serde_json::from_str(include_str!("../profiles/chrome-windows.json")).unwrap();
        let cases: Value =
            serde_json::from_str(include_str!("../tests/fixtures/profile-validation.json"))
                .unwrap();
        for case in cases.as_array().unwrap() {
            let mut value = base["fingerprint"].clone();
            for (key, item) in case["patch"].as_object().unwrap() {
                value[key] = item.clone();
            }
            if let Some(mutations) = case["mutations"].as_array() {
                for mutation in mutations {
                    let mut cursor = &mut value;
                    for key in mutation["path"].as_array().unwrap() {
                        cursor = &mut cursor[key.as_str().unwrap()];
                    }
                    *cursor = mutation["value"].clone();
                }
            }
            assert_eq!(
                apply_defaults(&value).is_ok(),
                case["valid"].as_bool().unwrap(),
                "{}",
                case["id"]
            );
        }
    }
    #[test]
    fn shipped_runtime_fingerprints_satisfy_contract() {
        for source in [
            include_str!("../profiles/chrome-windows.json"),
            include_str!("../profiles/edge-windows.json"),
            include_str!("../profiles/firefox-windows.json"),
        ] {
            let profile: Value = serde_json::from_str(source).unwrap();
            validate_fingerprint(&profile["fingerprint"]).unwrap();
        }
    }
    #[test]
    fn rejects_unknown_flags_and_nested_invalid_values() {
        let mut profile: Value =
            serde_json::from_str(include_str!("../profiles/chrome-windows.json")).unwrap();
        profile["fingerprint"]["enable_typo_spoof"] = Value::Bool(true);
        assert!(validate_fingerprint(&profile["fingerprint"]).is_err());
        profile["fingerprint"]
            .as_object_mut()
            .unwrap()
            .remove("enable_typo_spoof");
        profile["fingerprint"]["canvas_noise"]["noise_probability"] = serde_json::json!(2);
        assert!(validate_fingerprint(&profile["fingerprint"]).is_err());
    }
}
