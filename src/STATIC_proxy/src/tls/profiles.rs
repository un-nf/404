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

use std::hash::{Hash, Hasher};

use anyhow::{Context, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rustls::crypto::aws_lc_rs::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};
use rustls::crypto::aws_lc_rs::kx_group::{
    MLKEM768, SECP256R1, SECP256R1MLKEM768, SECP384R1, X25519, X25519MLKEM768,
};
use rustls::crypto::SupportedKxGroup;
use rustls::version::{TLS12, TLS13};
use rustls::{SupportedCipherSuite, SupportedProtocolVersion};
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, warn};
use uuid::Uuid;

/// Materialized TLS client plan derived from a profile's tls section.
#[derive(Debug, Clone)]
pub struct TlsClientPlan {
    pub(super) variant_id: String,
    pub(super) alpn: Vec<Vec<u8>>,
    pub(super) cipher_suites: Vec<&'static SupportedCipherSuite>,
    pub(super) protocol_versions: Vec<&'static SupportedProtocolVersion>,
    pub(super) kx_groups: Vec<&'static dyn SupportedKxGroup>,
}

impl TlsClientPlan {
    pub fn variant_id(&self) -> &str {
        &self.variant_id
    }

    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn
    }

    pub fn protocol_versions(&self) -> &[&'static SupportedProtocolVersion] {
        &self.protocol_versions
    }

    pub fn cipher_suites(&self) -> &[&'static SupportedCipherSuite] {
        &self.cipher_suites
    }

    pub fn owned_cipher_suites(&self) -> Vec<SupportedCipherSuite> {
        self.cipher_suites.iter().map(|suite| **suite).collect()
    }

    pub fn kx_groups(&self) -> &[&'static dyn SupportedKxGroup] {
        &self.kx_groups
    }

    pub fn clone_with_alpn(&self, alpn: Vec<Vec<u8>>) -> Self {
        Self {
            variant_id: self.variant_id.clone(),
            alpn,
            cipher_suites: self.cipher_suites.clone(),
            protocol_versions: self.protocol_versions.clone(),
            kx_groups: self.kx_groups.clone(),
        }
    }
}

/// Builds a TLS client plan from the `fingerprint_config` stored on a Flow.
pub fn plan_from_profile(profile: &Value, flow_id: Uuid) -> Result<Option<TlsClientPlan>> {
    let tls_value = match profile.get("tls") {
        Some(v) => v.clone(),
        None => return Ok(None),
    };

    if !tls_value
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .is_some()
    {
        debug!("profile missing tls schema_version; skipping TLS client plan");
        return Ok(None);
    }

    let schema: TlsSchema = serde_json::from_value(tls_value)
        .context("failed to parse tls schema block from profile")?;
    if schema.hello_variants.is_empty() {
        return Ok(None);
    }

    let variant = schema.select_variant(flow_id);
    let cipher_names = variant.resolve_cipher_sequence(&schema.cipher_catalog, flow_id);
    let cipher_suites: Vec<_> = cipher_names
        .iter()
        .filter_map(|name| lookup_cipher(name))
        .collect();
    if cipher_suites.is_empty() {
        warn!(variant = %variant.id, "TLS profile produced zero supported cipher suites");
    }

    let protocol_versions = schema.resolve_versions();
    let kx_groups = variant.resolve_kx_groups();
    if kx_groups.is_empty() {
        warn!(variant = %variant.id, "TLS profile produced zero supported key exchange groups");
    }
    let alpn = normalize_alpn(&variant.alpn);

    Ok(Some(TlsClientPlan {
        variant_id: variant.id.clone(),
        alpn,
        cipher_suites,
        protocol_versions,
        kx_groups,
    }))
}

fn normalize_alpn(entries: &[String]) -> Vec<Vec<u8>> {
    use std::collections::BTreeSet;

    let mut seen = BTreeSet::new();
    let mut normalized: Vec<Vec<u8>> = Vec::new();

    for val in entries {
        let lower = val.trim().to_ascii_lowercase();
        if lower == "h2" || lower == "http/1.1" {
            if seen.insert(lower.clone()) {
                normalized.push(lower.into_bytes());
            }
        }
    }

    if !seen.contains("http/1.1") {
        normalized.push(b"http/1.1".to_vec());
    }

    normalized
}

// --------------------------- Schema Types ---------------------------

#[derive(Debug, Clone, Deserialize)]
struct TlsSchema {
    schema_version: u16,
    versions: VersionBounds,
    cipher_catalog: CipherCatalog,
    #[serde(default)]
    hello_variants: Vec<HelloVariant>,
}

impl TlsSchema {
    fn select_variant(&self, flow_id: Uuid) -> &HelloVariant {
        if self.hello_variants.len() == 1 {
            return &self.hello_variants[0];
        }
        let total_weight: f64 = self.hello_variants.iter().map(|v| v.weight.max(0.0)).sum();
        if total_weight <= f64::EPSILON {
            return &self.hello_variants[0];
        }
        let mut rng = seeded_rng(flow_id, 0);
        let mut cursor = rng.gen::<f64>() * total_weight;
        for variant in &self.hello_variants {
            let weight = variant.weight.max(0.0);
            if cursor <= weight {
                return variant;
            }
            cursor -= weight;
        }
        self.hello_variants
            .last()
            .expect("hello_variants cannot be empty here")
    }

    fn resolve_versions(&self) -> Vec<&'static SupportedProtocolVersion> {
        let mut versions = Vec::new();
        if let Some(max) = parse_version(&self.versions.max) {
            versions.push(max);
        }
        if self.versions.allow_tls12_fallback {
            if let Some(min) = parse_version(&self.versions.min) {
                if versions.iter().all(|v| *v as *const _ != min as *const _) {
                    versions.push(min);
                }
            }
        }
        if versions.is_empty() {
            vec![&TLS13, &TLS12]
        } else {
            versions
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct VersionBounds {
    min: String,
    max: String,
    #[serde(default)]
    allow_tls12_fallback: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct CipherCatalog {
    #[serde(default)]
    tls13: Vec<CipherDescriptor>,
    #[serde(default)]
    tls12: Vec<CipherDescriptor>,
}

impl CipherCatalog {
    fn tls13_names(&self) -> Vec<String> {
        self.tls13.iter().map(|c| c.name.clone()).collect()
    }

    fn tls12_names(&self) -> Vec<String> {
        self.tls12.iter().map(|c| c.name.clone()).collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct CipherDescriptor {
    name: String,
    iana_id: u16,
}

#[derive(Debug, Clone, Deserialize)]
struct HelloVariant {
    id: String,
    #[serde(default = "default_variant_weight")]
    weight: f64,
    #[serde(default)]
    ja3: Option<String>,
    #[serde(default)]
    ja4: Option<String>,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    cipher_order: CipherOrder,
    #[serde(default)]
    cipher_permutations: Option<CipherPermutations>,
    #[serde(default)]
    supported_groups: Vec<String>,
    #[serde(default)]
    key_share_order: Vec<String>,
}

impl HelloVariant {
    fn resolve_cipher_sequence(&self, catalog: &CipherCatalog, flow_id: Uuid) -> Vec<String> {
        match self.cipher_order.mode {
            CipherOrderMode::Explicit => self.cipher_order.sequence.clone(),
            CipherOrderMode::Catalog => {
                let mut tls13 = self
                    .cipher_order
                    .tls13
                    .as_ref()
                    .map(|set| set.resolve(&catalog.tls13))
                    .unwrap_or_else(|| catalog.tls13_names());

                if let Some(perms) = &self.cipher_permutations {
                    if let Some(permuted) = perms.pick_tls13(flow_id) {
                        tls13 = permuted;
                    }
                }

                let tls12 = self
                    .cipher_order
                    .tls12
                    .as_ref()
                    .map(|set| set.resolve(&catalog.tls12))
                    .unwrap_or_else(|| catalog.tls12_names());

                if self.cipher_order.prefer_tls13 {
                    tls13.into_iter().chain(tls12.into_iter()).collect()
                } else {
                    tls12.into_iter().chain(tls13.into_iter()).collect()
                }
            }
        }
    }

    fn resolve_kx_groups(&self) -> Vec<&'static dyn SupportedKxGroup> {
        let mut names: Vec<String> = Vec::new();
        if !self.key_share_order.is_empty() {
            names.extend(self.key_share_order.iter().cloned());
        } else if !self.supported_groups.is_empty() {
            names.extend(self.supported_groups.iter().cloned());
        } else {
            names.extend(DEFAULT_KX_GROUPS.iter().map(|s| s.to_string()));
        }

        names
            .into_iter()
            .filter_map(|name| lookup_kx_group(&name))
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CipherOrderMode {
    Catalog,
    Explicit,
}

impl Default for CipherOrderMode {
    fn default() -> Self {
        CipherOrderMode::Catalog
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct CipherOrder {
    #[serde(default)]
    mode: CipherOrderMode,
    #[serde(default)]
    tls13: Option<CipherList>,
    #[serde(default)]
    tls12: Option<CipherList>,
    #[serde(default)]
    sequence: Vec<String>,
    #[serde(default = "prefer_tls13_default")]
    prefer_tls13: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum CipherList {
    Names(Vec<String>),
    CatalogDefault(String),
}

impl CipherList {
    fn resolve(&self, catalog: &[CipherDescriptor]) -> Vec<String> {
        match self {
            CipherList::Names(names) => names.clone(),
            CipherList::CatalogDefault(_) => catalog.iter().map(|c| c.name.clone()).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct CipherPermutations {
    #[serde(default)]
    tls13: Vec<Vec<String>>,
    #[serde(default = "default_selection")]
    selection: PermutationSelection,
    #[serde(default)]
    seed: Option<String>,
}

impl CipherPermutations {
    fn pick_tls13(&self, flow_id: Uuid) -> Option<Vec<String>> {
        if self.tls13.is_empty() {
            return None;
        }
        let mut rng = seeded_rng(flow_id, self.seed_hash());
        let idx = match self.selection {
            PermutationSelection::Uniform => rng.gen_range(0..self.tls13.len()),
        };
        self.tls13.get(idx).cloned()
    }

    fn seed_hash(&self) -> u64 {
        if let Some(seed) = &self.seed {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            seed.hash(&mut hasher);
            hasher.finish()
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PermutationSelection {
    Uniform,
}

fn lookup_cipher(name: &str) -> Option<&'static SupportedCipherSuite> {
    match name {
        "TLS_AES_128_GCM_SHA256" => Some(&TLS13_AES_128_GCM_SHA256),
        "TLS_AES_256_GCM_SHA384" => Some(&TLS13_AES_256_GCM_SHA384),
        "TLS_CHACHA20_POLY1305_SHA256" => Some(&TLS13_CHACHA20_POLY1305_SHA256),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => Some(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => Some(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
            Some(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
        }
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => Some(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => Some(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
            Some(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
        }
        _ => {
            tracing::debug!(cipher = name, "cipher not supported by rustls, skipping");
            None
        }
    }
}

fn lookup_kx_group(name: &str) -> Option<&'static dyn SupportedKxGroup> {
    match name.to_ascii_lowercase().as_str() {
        "x25519" => Some(X25519),
        "secp256r1" | "p256" => Some(SECP256R1),
        "secp384r1" | "p384" => Some(SECP384R1),
        "x25519mlkem768" => Some(X25519MLKEM768),
        "secp256r1mlkem768" => Some(SECP256R1MLKEM768),
        "mlkem768" => Some(MLKEM768),
        other => {
            debug!(group = other, "kx group not supported by rustls, skipping");
            None
        }
    }
}

const DEFAULT_KX_GROUPS: &[&str] = &["x25519", "secp256r1", "secp384r1"];

fn parse_version(label: &str) -> Option<&'static SupportedProtocolVersion> {
    match label.to_ascii_lowercase().as_str() {
        "tlsv1.3" | "tls13" => Some(&TLS13),
        "tlsv1.2" | "tls12" => Some(&TLS12),
        _ => None,
    }
}

fn default_variant_weight() -> f64 {
    1.0
}

fn prefer_tls13_default() -> bool {
    true
}

fn default_selection() -> PermutationSelection {
    PermutationSelection::Uniform
}

fn seeded_rng(flow_id: Uuid, salt: u64) -> StdRng {
    let bytes = flow_id.as_bytes();
    let mut left = [0u8; 8];
    let mut right = [0u8; 8];
    left.copy_from_slice(&bytes[0..8]);
    right.copy_from_slice(&bytes[8..16]);
    let base = u64::from_be_bytes(left) ^ u64::from_be_bytes(right) ^ salt;
    StdRng::seed_from_u64(base)
}
