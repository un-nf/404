//! The same constrained JSON Schema contract is read by Rust and JavaScript.
use anyhow::{bail, Result};
use serde_json::Value;
use std::sync::OnceLock;

fn schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| serde_json::from_str(include_str!("../schema/runtime-profile.schema.json")).expect("runtime schema"))
}

pub fn validate_fingerprint(value: &Value) -> Result<()> { validate(value, schema(), "fingerprint") }

fn validate(value: &Value, rule: &Value, path: &str) -> Result<()> {
    let expected: Vec<&str> = match rule.get("type") {
        Some(Value::String(kind)) => vec![kind.as_str()],
        Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if !expected.is_empty() && !expected.iter().any(|kind| match *kind {
        "object" => value.is_object(), "array" => value.is_array(), "string" => value.is_string(),
        "boolean" => value.is_boolean(), "null" => value.is_null(), "number" => value.is_number(),
        "integer" => value.as_f64().is_some_and(|number| number.is_finite() && number.fract() == 0.0 && number.abs() <= 9007199254740991.0),
        _ => false,
    }) { bail!("STATIC {path}: invalid type"); }
    if let Some(number) = value.as_f64() {
        if number < rule["minimum"].as_f64().unwrap_or(f64::NEG_INFINITY) || number > rule["maximum"].as_f64().unwrap_or(f64::INFINITY) {
            bail!("STATIC {path}: invalid range");
        }
    }
    if let Some(text) = value.as_str() {
        if text.chars().count() < rule["minLength"].as_u64().unwrap_or(0) as usize { bail!("STATIC {path}: empty string"); }
    }
    if let Some(choices) = rule["enum"].as_array() { if !choices.contains(value) { bail!("STATIC {path}: invalid enum"); } }
    if let Some(items) = value.as_array() {
        if let Some(item_rule) = rule.get("items") {
            for (index, item) in items.iter().enumerate() { validate(item, item_rule, &format!("{path}[{index}]"))?; }
        }
    } else if let Some(object) = value.as_object() {
        if let Some(required) = rule["required"].as_array() {
            for key in required.iter().filter_map(Value::as_str) { if !object.contains_key(key) { bail!("STATIC {path}.{key}: required"); } }
        }
        for (key, item) in object {
            let child = rule["properties"].get(key).or_else(|| rule.get("additionalProperties"));
            match child {
                Some(Value::Bool(false)) => bail!("STATIC {path}.{key}: unknown field"),
                Some(child) if child.is_object() => validate(item, child, &format!("{path}.{key}"))?,
                _ => {},
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shipped_runtime_fingerprints_satisfy_contract() {
        for source in [include_str!("../profiles/chrome-windows.json"),include_str!("../profiles/edge-windows.json"),include_str!("../profiles/firefox-windows.json")] {
            let profile: Value = serde_json::from_str(source).unwrap();
            validate_fingerprint(&profile["fingerprint"]).unwrap();
        }
    }
    #[test]
    fn rejects_unknown_flags_and_nested_invalid_values() {
        let mut profile: Value = serde_json::from_str(include_str!("../profiles/chrome-windows.json")).unwrap();
        profile["fingerprint"]["enable_typo_spoof"] = Value::Bool(true);
        assert!(validate_fingerprint(&profile["fingerprint"]).is_err());
        profile["fingerprint"].as_object_mut().unwrap().remove("enable_typo_spoof");
        profile["fingerprint"]["canvas_noise"]["noise_probability"] = serde_json::json!(2);
        assert!(validate_fingerprint(&profile["fingerprint"]).is_err());
    }
}
