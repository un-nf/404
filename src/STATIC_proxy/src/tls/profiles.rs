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
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, warn};
use uuid::Uuid;

/// Materialized TLS client plan derived from a profile's tls section.
#[derive(Debug, Clone)]
pub struct TlsClientPlan {
    pub(super) variant_id: String,
    pub(super) alpn: Vec<String>,
    pub(super) cipher_suites: Vec<String>,
    pub(super) min_tls_version: Option<ProfileTlsVersion>,
    pub(super) max_tls_version: Option<ProfileTlsVersion>,
    pub(super) supported_groups: Vec<String>,
    pub(super) key_share_order: Vec<String>,
    pub(super) signature_algorithms: Vec<String>,
    pub(super) extension_sequence: Vec<String>,
    pub(super) session_ticket: bool,
    pub(super) psk_dhe_ke: bool,
    pub(super) renegotiation: bool,
    pub(super) enable_ocsp_stapling: bool,
    pub(super) enable_signed_cert_timestamps: bool,
    pub(super) grease_enabled: Option<bool>,
    pub(super) permute_extensions: Option<bool>,
    pub(super) enable_ech_grease: bool,
    pub(super) record_size_limit: Option<u16>,
    pub(super) delegated_credentials: Option<String>,
    pub(super) preserve_tls13_cipher_list: bool,
    pub(super) http2: Option<Http2Plan>,
}

impl TlsClientPlan {
    pub fn variant_id(&self) -> &str {
        &self.variant_id
    }

    pub fn alpn_protocols(&self) -> &[String] {
        &self.alpn
    }

    pub fn min_tls_version(&self) -> Option<ProfileTlsVersion> {
        self.min_tls_version
    }

    pub fn max_tls_version(&self) -> Option<ProfileTlsVersion> {
        self.max_tls_version
    }

    pub fn cipher_suites(&self) -> &[String] {
        &self.cipher_suites
    }

    pub fn supported_groups(&self) -> &[String] {
        &self.supported_groups
    }

    pub fn key_share_order(&self) -> &[String] {
        &self.key_share_order
    }

    pub fn signature_algorithms(&self) -> &[String] {
        &self.signature_algorithms
    }

    pub fn extension_sequence(&self) -> &[String] {
        &self.extension_sequence
    }

    pub fn session_ticket(&self) -> bool {
        self.session_ticket
    }

    pub fn psk_dhe_ke(&self) -> bool {
        self.psk_dhe_ke
    }

    pub fn renegotiation(&self) -> bool {
        self.renegotiation
    }

    pub fn enable_ocsp_stapling(&self) -> bool {
        self.enable_ocsp_stapling
    }

    pub fn enable_signed_cert_timestamps(&self) -> bool {
        self.enable_signed_cert_timestamps
    }

    pub fn grease_enabled(&self) -> Option<bool> {
        self.grease_enabled
    }

    pub fn permute_extensions(&self) -> Option<bool> {
        self.permute_extensions
    }

    pub fn enable_ech_grease(&self) -> bool {
        self.enable_ech_grease
    }

    pub fn record_size_limit(&self) -> Option<u16> {
        self.record_size_limit
    }

    pub fn delegated_credentials(&self) -> Option<&str> {
        self.delegated_credentials.as_deref()
    }

    pub fn preserve_tls13_cipher_list(&self) -> bool {
        self.preserve_tls13_cipher_list
    }

    pub fn http2(&self) -> Option<&Http2Plan> {
        self.http2.as_ref()
    }

    pub fn clone_with_alpn(&self, alpn: Vec<String>) -> Self {
        Self {
            variant_id: self.variant_id.clone(),
            alpn,
            cipher_suites: self.cipher_suites.clone(),
            min_tls_version: self.min_tls_version,
            max_tls_version: self.max_tls_version,
            supported_groups: self.supported_groups.clone(),
            key_share_order: self.key_share_order.clone(),
            signature_algorithms: self.signature_algorithms.clone(),
            extension_sequence: self.extension_sequence.clone(),
            session_ticket: self.session_ticket,
            psk_dhe_ke: self.psk_dhe_ke,
            renegotiation: self.renegotiation,
            enable_ocsp_stapling: self.enable_ocsp_stapling,
            enable_signed_cert_timestamps: self.enable_signed_cert_timestamps,
            grease_enabled: self.grease_enabled,
            permute_extensions: self.permute_extensions,
            enable_ech_grease: self.enable_ech_grease,
            record_size_limit: self.record_size_limit,
            delegated_credentials: self.delegated_credentials.clone(),
            preserve_tls13_cipher_list: self.preserve_tls13_cipher_list,
            http2: self.http2.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(alpn: Vec<String>) -> Self {
        Self {
            variant_id: "test_variant".to_string(),
            alpn,
            cipher_suites: Vec::new(),
            min_tls_version: None,
            max_tls_version: None,
            supported_groups: Vec::new(),
            key_share_order: Vec::new(),
            signature_algorithms: Vec::new(),
            extension_sequence: Vec::new(),
            session_ticket: true,
            psk_dhe_ke: true,
            renegotiation: false,
            enable_ocsp_stapling: false,
            enable_signed_cert_timestamps: false,
            grease_enabled: Some(true),
            permute_extensions: None,
            enable_ech_grease: false,
            record_size_limit: None,
            delegated_credentials: None,
            preserve_tls13_cipher_list: true,
            http2: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileTlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Http2Plan {
    pub initial_stream_id: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub initial_max_send_streams: Option<usize>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
    pub enable_connect_protocol: Option<bool>,
    pub no_rfc7540_priorities: Option<bool>,
    pub max_concurrent_streams: Option<u32>,
    pub max_concurrent_reset_streams: Option<usize>,
    pub max_pending_accept_reset_streams: Option<usize>,
    pub max_send_buffer_size: Option<usize>,
    pub adaptive_window: Option<bool>,
    pub pseudo_header_order: Vec<String>,
    pub settings_order: Vec<String>,
    pub headers_stream_dependency: Option<Http2StreamDependencyPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Http2StreamDependencyPlan {
    pub stream_id: u32,
    pub weight: u8,
    pub exclusive: bool,
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
    let cipher_suites = variant.resolve_cipher_sequence(&schema.cipher_catalog, flow_id);
    if cipher_suites.is_empty() {
        warn!(variant = %variant.id, "TLS profile produced zero supported cipher suites");
    }

    let (min_tls_version, max_tls_version) = schema.resolve_versions();
    let supported_groups = variant.resolve_supported_groups();
    if supported_groups.is_empty() {
        warn!(variant = %variant.id, "TLS profile produced zero supported key exchange groups");
    }
    let alpn = normalize_alpn(&variant.alpn);
    let extension_sequence = variant.resolve_extension_names();
    let enable_ocsp_stapling = contains_extension(&extension_sequence, "status_request");
    let enable_signed_cert_timestamps = contains_extension(
        &extension_sequence,
        "signed_certificate_timestamp",
    ) || contains_extension(&extension_sequence, "certificate_timestamp");
    let renegotiation = contains_extension(&extension_sequence, "renegotiation_info");
    let session_ticket = variant
        .session_resumption
        .as_ref()
        .map(|resumption| resumption.enable_tickets)
        .unwrap_or(true);
    let psk_dhe_ke = if variant.psk_key_exchange_modes.is_empty() {
        true
    } else {
        variant
            .psk_key_exchange_modes
            .iter()
            .any(|mode| mode.eq_ignore_ascii_case("psk_dhe_ke"))
    };
    let record_size_limit = variant
        .record_layer
        .as_ref()
        .and_then(|layer| layer.max_fragment)
        .and_then(|value| u16::try_from(value).ok());
    let has_explicit_extension_order = !extension_sequence.is_empty();
    let grease_enabled = Some(
        schema.handshake_features.grease || contains_extension(&extension_sequence, "grease"),
    );
    let permute_extensions = if has_explicit_extension_order {
        Some(false)
    } else {
        None
    };

    Ok(Some(TlsClientPlan {
        variant_id: variant.id.clone(),
        alpn,
        cipher_suites,
        min_tls_version,
        max_tls_version,
        supported_groups: supported_groups.clone(),
        key_share_order: variant.resolve_key_share_order(),
        signature_algorithms: variant.signature_algorithms.clone(),
        extension_sequence,
        session_ticket,
        psk_dhe_ke,
        renegotiation,
        enable_ocsp_stapling,
        enable_signed_cert_timestamps,
        grease_enabled,
        permute_extensions,
        enable_ech_grease: false,
        record_size_limit,
        delegated_credentials: None,
        preserve_tls13_cipher_list: true,
        http2: schema.http2.as_ref().map(Http2Profile::to_plan),
    }))
}

pub fn validate_profile_coherence(profile: &Value) -> Vec<String> {
    let mut warnings = Vec::new();

    let Some(tls_value) = profile.get("tls") else {
        return warnings;
    };

    let Ok(schema) = serde_json::from_value::<TlsSchema>(tls_value.clone()) else {
        warnings.push("TLS schema could not be parsed for support validation; outbound fingerprint support may be incomplete".to_string());
        return warnings;
    };

    if schema.schema_version != 2 {
        warnings.push(format!(
            "TLS schema_version '{}' is not explicitly validated by the current wreq adapter",
            schema.schema_version
        ));
    }

    if schema.cipher_catalog.contains_named_iana_ids() {
        warnings.push(
            "TLS cipher_catalog iana_id values are metadata only; the outbound adapter uses cipher names".to_string(),
        );
    }

    let Some(browser) = profile
        .get("fingerprint")
        .and_then(|fingerprint| {
            fingerprint
                .get("browser_type")
                .or_else(|| fingerprint.get("browser"))
        })
        .and_then(|value| value.as_str())
        .map(|value| value.to_ascii_lowercase())
    else {
        return warnings;
    };

    let expected_os = profile
        .get("fingerprint")
        .and_then(|fingerprint| fingerprint.get("os"))
        .and_then(|value| value.as_str())
        .map(|value| value.to_ascii_lowercase());

    let Some(variants) = profile
        .get("tls")
        .and_then(|tls| tls.get("hello_variants"))
        .and_then(|variants| variants.as_array())
    else {
        return warnings;
    };

    for (variant, raw_variant) in schema.hello_variants.iter().zip(variants.iter()) {
        let id = variant.id.as_str();

        for group in &variant.supported_groups {
            if !is_supported_wreq_curve_name(group) {
                warnings.push(format!(
                    "TLS variant '{id}' declares supported group '{group}', but the current wreq adapter cannot apply that curve"
                ));
            }
        }

        for group in &variant.key_share_order {
            if !is_supported_wreq_curve_name(group) {
                warnings.push(format!(
                    "TLS variant '{id}' declares key share '{group}', but the current wreq adapter cannot apply that curve"
                ));
            }
        }

        if let Some(ja3) = variant.ja3.as_deref() {
            warnings.push(format!(
                "TLS variant '{id}' declares JA3 '{ja3}', but JA3 is documentation-only until wire output is verified"
            ));
        }

        if let Some(ja4) = variant.ja4.as_deref() {
            warnings.push(format!(
                "TLS variant '{id}' declares JA4 '{ja4}', but JA4 is documentation-only until wire output is verified"
            ));
        }

        if variant.alpn.iter().any(|value| value.eq_ignore_ascii_case("h3")) {
            warnings.push(format!(
                "TLS variant '{id}' advertises h3 in ALPN, but the current outbound TCP transport only applies h2/http/1.1"
            ));
        }

        if !variant.extension_sequence.is_empty() {
            warnings.push(format!(
                "TLS variant '{id}' specifies an explicit extension sequence, but the current wreq adapter cannot enforce extension ordering by type"
            ));
        }

        if let Some(resumption) = variant.session_resumption.as_ref() {
            if resumption.max_early_data.is_some() {
                warnings.push(format!(
                    "TLS variant '{id}' sets session_resumption.max_early_data, but the current adapter does not control early data behavior"
                ));
            }

            if resumption.ticket_lifetime_seconds.is_some() {
                warnings.push(format!(
                    "TLS variant '{id}' sets session_resumption.ticket_lifetime_seconds, but the current adapter does not control ticket lifetime hints"
                ));
            }
        }

        if let Some(record_layer) = variant.record_layer.as_ref() {
            if let Some(padding_strategy) = record_layer.padding_strategy.as_deref() {
                warnings.push(format!(
                    "TLS variant '{id}' sets record_layer.padding_strategy='{padding_strategy}', but the current adapter does not control TLS record padding strategy"
                ));
            }
        }

        let Some(id) = raw_variant.get("id").and_then(|value| value.as_str()) else {
            continue;
        };

        if !variant_matches_browser(id, &browser) {
            warnings.push(format!(
                "TLS variant '{id}' does not match advertised browser family '{browser}'"
            ));
        }

        if let Some(os) = expected_os.as_deref() {
            if let Some(variant_os) = detect_variant_os(id) {
                if variant_os != os {
                    warnings.push(format!(
                        "TLS variant '{id}' appears to target '{variant_os}' but fingerprint advertises '{os}'"
                    ));
                }
            }
        }
    }

    if let Some(http2) = schema.http2.as_ref() {
        if http2.initial_max_send_streams.is_some() {
            warnings.push(
                "TLS http2.initial_max_send_streams is parsed but not applied by the current wreq adapter".to_string(),
            );
        }

        if http2.max_concurrent_reset_streams.is_some() {
            warnings.push(
                "TLS http2.max_concurrent_reset_streams is parsed but not applied by the current wreq adapter".to_string(),
            );
        }

        if http2.max_pending_accept_reset_streams.is_some() {
            warnings.push(
                "TLS http2.max_pending_accept_reset_streams is parsed but not applied by the current wreq adapter".to_string(),
            );
        }

        if http2.max_send_buffer_size.is_some() {
            warnings.push(
                "TLS http2.max_send_buffer_size is parsed but not applied by the current wreq adapter".to_string(),
            );
        }

        if http2.adaptive_window.is_some() {
            warnings.push(
                "TLS http2.adaptive_window is parsed but not applied by the current wreq adapter".to_string(),
            );
        }
    }

    warnings
}

fn normalize_alpn(entries: &[String]) -> Vec<String> {
    use std::collections::BTreeSet;

    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();

    for val in entries {
        let lower = val.trim().to_ascii_lowercase();
        if lower == "h2" || lower == "http/1.1" || lower == "h3" {
            if seen.insert(lower.clone()) {
                normalized.push(lower);
            }
        }
    }

    if !seen.contains("http/1.1") {
        normalized.push("http/1.1".to_string());
    }

    normalized
}

fn contains_extension(extensions: &[String], expected: &str) -> bool {
    extensions
        .iter()
        .any(|value| value.eq_ignore_ascii_case(expected))
}

fn variant_matches_browser(variant_id: &str, browser: &str) -> bool {
    let lower = variant_id.to_ascii_lowercase();
    match browser {
        "firefox" => lower.starts_with("ff_") || lower.contains("firefox"),
        "chrome" | "chromium" => {
            lower.starts_with("ch_") || lower.contains("chrome") || lower.contains("chromium")
        }
        "edge" => lower.starts_with("edge_") || lower.contains("edge"),
        _ => true,
    }
}

fn detect_variant_os(variant_id: &str) -> Option<&'static str> {
    let lower = variant_id.to_ascii_lowercase();
    if lower.contains("windows") || lower.contains("win") {
        Some("windows")
    } else if lower.contains("android") {
        Some("android")
    } else if lower.contains("linux") {
        Some("linux")
    } else if lower.contains("mac") || lower.contains("osx") || lower.contains("darwin") {
        Some("macos")
    } else if lower.contains("ios") || lower.contains("iphone") || lower.contains("ipad") {
        Some("ios")
    } else {
        None
    }
}

// --------------------------- Schema Types ---------------------------

#[derive(Debug, Clone, Deserialize)]
struct TlsSchema {
    schema_version: u16,
    versions: VersionBounds,
    cipher_catalog: CipherCatalog,
    #[serde(default)]
    hello_variants: Vec<HelloVariant>,
    #[serde(default)]
    handshake_features: HandshakeFeatures,
    #[serde(default)]
    http2: Option<Http2Profile>,
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

    fn resolve_versions(&self) -> (Option<ProfileTlsVersion>, Option<ProfileTlsVersion>) {
        let max = parse_version(&self.versions.max).or(parse_version(&self.versions.min));
        let min = if self.versions.allow_tls12_fallback {
            parse_version(&self.versions.min).or(max)
        } else {
            max
        };

        (min, max)
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct HandshakeFeatures {
    #[serde(default)]
    grease: bool,
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

    fn contains_named_iana_ids(&self) -> bool {
        self.tls13.iter().any(CipherDescriptor::has_iana_id_metadata)
            || self.tls12.iter().any(CipherDescriptor::has_iana_id_metadata)
    }
}

fn is_supported_wreq_curve_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "x25519"
            | "secp256r1"
            | "p256"
            | "secp384r1"
            | "p384"
            | "secp521r1"
            | "p521"
            | "x25519mlkem768"
    )
}

#[derive(Debug, Clone, Deserialize)]
struct CipherDescriptor {
    name: String,
    #[serde(default)]
    iana_id: u16,
}

impl CipherDescriptor {
    fn has_iana_id_metadata(&self) -> bool {
        self.iana_id != 0
    }
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
    #[serde(default)]
    signature_algorithms: Vec<String>,
    #[serde(default)]
    extension_sequence: Vec<ExtensionDescriptor>,
    #[serde(default)]
    psk_key_exchange_modes: Vec<String>,
    #[serde(default)]
    session_resumption: Option<SessionResumption>,
    #[serde(default)]
    record_layer: Option<RecordLayer>,
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

    fn resolve_supported_groups(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        if !self.key_share_order.is_empty() {
            names.extend(self.key_share_order.iter().cloned());
        } else if !self.supported_groups.is_empty() {
            names.extend(self.supported_groups.iter().cloned());
        } else {
            names.extend(DEFAULT_SUPPORTED_GROUPS.iter().map(|s| s.to_string()));
        }

        names
    }

    fn resolve_key_share_order(&self) -> Vec<String> {
        if !self.key_share_order.is_empty() {
            return self.key_share_order.clone();
        }

        self.resolve_supported_groups()
    }

    fn resolve_extension_names(&self) -> Vec<String> {
        self.extension_sequence
            .iter()
            .map(|extension| extension.normalized_name())
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ExtensionDescriptor {
    #[serde(default)]
    code: String,
    #[serde(default)]
    name: String,
}

impl ExtensionDescriptor {
    fn normalized_name(&self) -> String {
        if !self.name.is_empty() {
            return self.name.trim().to_ascii_lowercase();
        }

        self.code.trim().to_ascii_lowercase()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SessionResumption {
    #[serde(default = "default_true")]
    enable_tickets: bool,
    #[serde(default)]
    max_early_data: Option<u32>,
    #[serde(default)]
    ticket_lifetime_seconds: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordLayer {
    #[serde(default)]
    max_fragment: Option<u32>,
    #[serde(default)]
    padding_strategy: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Http2Profile {
    #[serde(default)]
    initial_stream_id: Option<u32>,
    #[serde(default)]
    initial_window_size: Option<u32>,
    #[serde(default)]
    initial_connection_window_size: Option<u32>,
    #[serde(default)]
    initial_max_send_streams: Option<usize>,
    #[serde(default)]
    max_frame_size: Option<u32>,
    #[serde(default)]
    max_header_list_size: Option<u32>,
    #[serde(default)]
    header_table_size: Option<u32>,
    #[serde(default)]
    enable_push: Option<bool>,
    #[serde(default)]
    enable_connect_protocol: Option<bool>,
    #[serde(default)]
    no_rfc7540_priorities: Option<bool>,
    #[serde(default)]
    max_concurrent_streams: Option<u32>,
    #[serde(default)]
    max_concurrent_reset_streams: Option<usize>,
    #[serde(default)]
    max_pending_accept_reset_streams: Option<usize>,
    #[serde(default)]
    max_send_buffer_size: Option<usize>,
    #[serde(default)]
    adaptive_window: Option<bool>,
    #[serde(default)]
    pseudo_header_order: Vec<String>,
    #[serde(default)]
    settings_order: Vec<String>,
    #[serde(default)]
    headers_stream_dependency: Option<Http2StreamDependencyProfile>,
}

impl Http2Profile {
    fn to_plan(&self) -> Http2Plan {
        Http2Plan {
            initial_stream_id: self.initial_stream_id,
            initial_window_size: self.initial_window_size,
            initial_connection_window_size: self.initial_connection_window_size,
            initial_max_send_streams: self.initial_max_send_streams,
            max_frame_size: self.max_frame_size,
            max_header_list_size: self.max_header_list_size,
            header_table_size: self.header_table_size,
            enable_push: self.enable_push,
            enable_connect_protocol: self.enable_connect_protocol,
            no_rfc7540_priorities: self.no_rfc7540_priorities,
            max_concurrent_streams: self.max_concurrent_streams,
            max_concurrent_reset_streams: self.max_concurrent_reset_streams,
            max_pending_accept_reset_streams: self.max_pending_accept_reset_streams,
            max_send_buffer_size: self.max_send_buffer_size,
            adaptive_window: self.adaptive_window,
            pseudo_header_order: self.pseudo_header_order.clone(),
            settings_order: self.settings_order.clone(),
            headers_stream_dependency: self
                .headers_stream_dependency
                .as_ref()
                .map(Http2StreamDependencyProfile::to_plan),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Http2StreamDependencyProfile {
    #[serde(default)]
    stream_id: u32,
    weight: u8,
    #[serde(default)]
    exclusive: bool,
}

impl Http2StreamDependencyProfile {
    fn to_plan(&self) -> Http2StreamDependencyPlan {
        Http2StreamDependencyPlan {
            stream_id: self.stream_id,
            weight: self.weight,
            exclusive: self.exclusive,
        }
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
            CipherList::CatalogDefault(selector) => {
                if !selector.eq_ignore_ascii_case("default") {
                    debug!(selector, "unsupported cipher catalog selector in profile; using catalog order");
                }
                catalog.iter().map(|c| c.name.clone()).collect()
            }
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

const DEFAULT_SUPPORTED_GROUPS: &[&str] = &["x25519", "secp256r1", "secp384r1"];

fn parse_version(label: &str) -> Option<ProfileTlsVersion> {
    match label.to_ascii_lowercase().as_str() {
        "tlsv1.3" | "tls13" => Some(ProfileTlsVersion::Tls13),
        "tlsv1.2" | "tls12" => Some(ProfileTlsVersion::Tls12),
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

fn default_true() -> bool {
    true
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

#[cfg(test)]
mod tests {
    use super::validate_profile_coherence;
    use serde_json::Value;

    #[test]
    fn validate_profile_coherence_accepts_matching_browser_family() {
        let profile = serde_json::json!({
            "fingerprint": {
                "browser_type": "chrome",
                "os": "Windows"
            },
            "tls": {
                "hello_variants": [
                    { "id": "ch_h3_release_a" },
                    { "id": "ch_h3_release_b" }
                ]
            }
        });

        assert!(validate_profile_coherence(&profile).is_empty());
    }

    #[test]
    fn validate_profile_coherence_flags_browser_and_os_mismatch() {
        let profile = serde_json::json!({
            "fingerprint": {
                "browser_type": "chrome",
                "os": "Windows"
            },
            "tls": {
                "hello_variants": [
                    { "id": "firefox_143_linux" }
                ]
            }
        });

        let warnings = validate_profile_coherence(&profile);

        assert!(warnings.iter().any(|warning| warning.contains("browser family 'chrome'")));
        assert!(warnings.iter().any(|warning| warning.contains("advertises 'windows'")));
    }

    #[test]
    fn validate_profile_coherence_flags_descriptive_and_unsupported_tls_fields() {
        let profile = serde_json::json!({
            "fingerprint": {
                "browser_type": "chrome",
                "os": "Windows"
            },
            "tls": {
                "schema_version": 2,
                "versions": {
                    "min": "TLSv1.2",
                    "max": "TLSv1.3",
                    "allow_tls12_fallback": true
                },
                "cipher_catalog": {
                    "tls13": [
                        { "name": "TLS_AES_128_GCM_SHA256", "iana_id": 4865 }
                    ],
                    "tls12": []
                },
                "hello_variants": [
                    {
                        "id": "ch_h3_release_a",
                        "ja3": "771,...",
                        "ja4": "q13...",
                        "alpn": ["h3", "h2"],
                        "extension_sequence": [
                            { "name": "server_name" },
                            { "name": "supported_versions" }
                        ],
                        "session_resumption": {
                            "enable_tickets": true,
                            "max_early_data": 0,
                            "ticket_lifetime_seconds": 43200
                        },
                        "record_layer": {
                            "max_fragment": 16384,
                            "padding_strategy": "chrome"
                        }
                    }
                ],
                "http2": {
                    "initial_max_send_streams": 32,
                    "max_concurrent_reset_streams": 8,
                    "max_pending_accept_reset_streams": 4,
                    "max_send_buffer_size": 65535,
                    "adaptive_window": true
                }
            }
        });

        let warnings = validate_profile_coherence(&profile);

        assert!(warnings.iter().any(|warning| warning.contains("iana_id values are metadata only")));
        assert!(warnings.iter().any(|warning| warning.contains("declares JA3")));
        assert!(warnings.iter().any(|warning| warning.contains("declares JA4")));
        assert!(warnings.iter().any(|warning| warning.contains("advertises h3 in ALPN")));
        assert!(warnings.iter().any(|warning| warning.contains("explicit extension sequence")));
        assert!(warnings.iter().any(|warning| warning.contains("max_early_data")));
        assert!(warnings.iter().any(|warning| warning.contains("ticket_lifetime_seconds")));
        assert!(warnings.iter().any(|warning| warning.contains("padding_strategy='chrome'")));
        assert!(warnings.iter().any(|warning| warning.contains("initial_max_send_streams")));
        assert!(warnings.iter().any(|warning| warning.contains("adaptive_window")));
    }

    #[test]
    fn shipped_firefox_profile_is_clean_for_live_wreq_adapter() {
        let profile: Value = serde_json::from_str(include_str!("../../profiles/firefox-windows.json"))
            .expect("firefox-windows.json should parse");

        let warnings = validate_profile_coherence(&profile);

        assert!(warnings.is_empty(), "unexpected Firefox profile warnings: {warnings:?}");
    }

    #[test]
    fn shipped_chrome_profile_is_clean_for_live_wreq_adapter() {
        let profile: Value = serde_json::from_str(include_str!("../../profiles/chrome-windows.json"))
            .expect("chrome-windows.json should parse");

        let warnings = validate_profile_coherence(&profile);

        assert!(warnings.is_empty(), "unexpected Chrome profile warnings: {warnings:?}");
    }
}
