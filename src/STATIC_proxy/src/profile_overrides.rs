//! Explicit advertised values; never read host disk measurements.
use anyhow::{bail, Result};
use serde::Deserialize;
use serde_json::Value;

pub const MAX_SAFE_BYTES: u64 = 9_007_199_254_740_991;

fn profile_bytes(value: &Value) -> Option<u64> {
    value.as_f64().filter(|number| number.is_finite() && *number>=0.0 && number.fract()==0.0 && *number<=MAX_SAFE_BYTES as f64).map(|number| number as u64)
}

pub fn parse_storage_bytes(text: &str) -> Result<u64> {
    let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    if split == 0 { bail!("storage size requires an unsigned integer and optional B/KiB/MiB/GiB/TiB suffix"); }
    let amount: u64 = text[..split].parse()?;
    let multiplier = match &text[split..] {
        "" | "B" => 1, "KiB" => 1 << 10, "MiB" => 1 << 20,
        "GiB" => 1 << 30, "TiB" => 1 << 40,
        _ => bail!("unknown storage size suffix"),
    };
    let bytes = amount.checked_mul(multiplier).filter(|n| *n <= MAX_SAFE_BYTES)
        .ok_or_else(|| anyhow::anyhow!("storage size exceeds JavaScript safe integer range"))?;
    Ok(bytes)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageOverrides {
    pub preset: Option<String>,
    pub quota: Option<u64>,
    pub usage: Option<u64>,
}

impl StorageOverrides {
    pub fn apply(&self, profile: &mut Value) -> Result<()> {
        let preset = match self.preset.as_deref() {
            None => None, Some("lower") => Some(10_u64 << 30),
            Some("standard") => Some(50_u64 << 30), Some("higher") => Some(100_u64 << 30),
            Some(_) => bail!("storage preset must be lower, standard or higher"),
        };
        let explicit=self.preset.is_some()||self.quota.is_some()||self.usage.is_some();
        let Some(fp) = profile.get_mut("fingerprint").and_then(Value::as_object_mut) else {
            if explicit {bail!("advertised storage overrides require a runtime fingerprint profile");}
            return Ok(());
        };
        // Transport-only profiles do not acquire a fabricated JS persona.
        if !fp.contains_key("canvas_hash") {
            if explicit {bail!("advertised storage overrides require a runtime fingerprint profile");}
            return Ok(());
        }
        for key in ["storage_quota", "storage_usage"] {
            if fp.get(key).is_some_and(|value| profile_bytes(value).is_none()) { bail!("invalid profile {key}"); }
        }
        let quota = self.quota.or(preset).or_else(|| fp.get("storage_quota").and_then(profile_bytes)).unwrap_or(50_u64 << 30);
        let usage = self.usage.or_else(|| fp.get("storage_usage").and_then(profile_bytes)).unwrap_or(1 << 20);
        if quota == 0 || quota > MAX_SAFE_BYTES || usage > quota { bail!("invalid advertised storage: require 0 <= usage <= positive safe-integer quota"); }
        fp.remove("storage_usage_quantum");
        fp.insert("storage_quota".into(), quota.into()); fp.insert("storage_usage".into(), usage.into());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_units_reject_ambiguous_overflow_and_invalid_values() {
        assert_eq!(parse_storage_bytes("50GiB").unwrap(), 50 << 30);
        assert_eq!(parse_storage_bytes("1MiB").unwrap(), 1 << 20);
        for text in ["-1", "NaN", "1.5GiB", "10GB", " 1", "9007199254740992", "18446744073709551615TiB"] { assert!(parse_storage_bytes(text).is_err(), "{text}"); }
    }
    #[test]
    fn explicit_values_preset_profile_and_migration_resolve_once() {
        let mut decimal:Value=serde_json::from_str(r#"{"fingerprint":{"canvas_hash":"test","storage_quota":100.0,"storage_usage":1.0}}"#).unwrap();
        StorageOverrides::default().apply(&mut decimal).unwrap();
        assert_eq!(decimal["fingerprint"]["storage_quota"],100);assert_eq!(decimal["fingerprint"]["storage_usage"],1);
        let base = serde_json::json!({"fingerprint":{"canvas_hash":"test","storage_quota":123,"storage_usage":7,"storage_usage_quantum":10}});
        for (preset, quota) in [("lower",10_u64 << 30),("standard",50 << 30),("higher",100 << 30)] {
            let mut value=base.clone();StorageOverrides{preset:Some(preset.into()),..Default::default()}.apply(&mut value).unwrap();
            assert_eq!(value["fingerprint"]["storage_quota"],quota);assert_eq!(value["fingerprint"]["storage_usage"],7);
        }
        let mut value=base.clone();StorageOverrides{preset:Some("lower".into()),quota:Some(456),usage:Some(8)}.apply(&mut value).unwrap();
        assert_eq!(value["fingerprint"]["storage_quota"],456);assert!(value["fingerprint"].get("storage_usage_quantum").is_none());
        let mut value=serde_json::json!({"fingerprint":{"canvas_hash":"test"}});StorageOverrides::default().apply(&mut value).unwrap();assert_eq!(value["fingerprint"]["storage_quota"],50_u64 << 30);
        assert!(StorageOverrides{quota:Some(1),usage:Some(2),..Default::default()}.apply(&mut value).is_err());
    }
}
