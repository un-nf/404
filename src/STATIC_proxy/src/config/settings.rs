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
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Configuration loaders and structures for the STATIC proxy.
///
/// These types mirror `static.example.toml`, apply sane defaults, and normalize any
/// operator-supplied relative paths so downstream components can assume absolute inputs
/// where it is safe to do so.
#[derive(Debug, Clone, Deserialize)]
/// Top-level configuration parsed from the STATIC TOML file.
///
/// Each nested struct captures one subsystem (listener, TLS, pipeline, HTTP/3, telemetry)
/// so changes can stay localized and audit-friendly.
pub struct StaticConfig {
    /// Listener configuration (bind address, port, and protocol expectations).
    pub listener: ListenerConfig,
    /// TLS configuration (on-disk CA material and cache layout).
    pub tls: TlsConfig,
    /// Pipeline configuration (profile lookup paths plus stage toggles).
    pub pipeline: PipelineConfig,
    /// HTTP/3 runtime configuration (QUIC listener options and feature gating).
    #[serde(default)]
    pub http3: Http3Config,
    /// Telemetry configuration (stdout vs structured log output).
    pub telemetry: TelemetryConfig,
}

impl StaticConfig {
    /// Reads the config file, deserializes TOML, and normalizes safe relative paths.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let mut cfg: StaticConfig = toml::from_str(&raw)
            .with_context(|| format!("invalid STATIC config: {}", path.display()))?;

        let base_dir = path.parent();
        Self::absolutize_dir(base_dir, &mut cfg.pipeline.profiles_path);

        Ok(cfg)
    }

    /// Helper that resolves relative directories against the config file's location.
    fn absolutize_dir(base_dir: Option<&Path>, target: &mut PathBuf) {
        if target.is_relative() {
            if let Some(dir) = base_dir {
                *target = dir.join(&*target);
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    /// Bind address for the TLS listener (defaults to loopback for local testing).
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// TCP port used for inbound client connections.
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    /// Whether clients speak TLS (default) or plaintext HTTP into the proxy.
    #[serde(default)]
    pub proxy_protocol: ProxyProtocol,
}

/// Default listener bind address (loopback).
fn default_bind_address() -> String {
    "127.0.0.1".into()
}

/// Default listener port when none is provided.
fn default_bind_port() -> u16 {
    8443
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    /// Terminate TLS inline before parsing HTTP.
    Tls,
    /// Treat the socket as plaintext HTTP (useful for testing).
    Plain,
}

impl Default for ProxyProtocol {
    fn default() -> Self {
        ProxyProtocol::Tls
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Path to the CA certificate browsers must trust for interception.
    pub ca_cert_path: PathBuf,
    /// Path to the CA private key used for leaf issuance.
    pub ca_key_path: PathBuf,
    /// Directory used for caching generated leaf certificates per hostname.
    pub cache_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineConfig {
    /// Path to the fingerprint profile directory or JSON bundle (relative paths resolve beside the config file).
    pub profiles_path: PathBuf,
    /// Profile name applied when routing logic does not override the fingerprint plan.
    #[serde(default = "default_profile_name")]
    pub default_profile: String,
    /// Turns on verbose JS injection logging so CSP/script issues are easier to spot.
    #[serde(default)]
    pub js_debug: bool,
    /// Strategy for Alt-Svc header handling (remove, normalize, or redirect for HTTP/3 suppression).
    #[serde(default)]
    pub alt_svc_strategy: AltSvcStrategy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Http3Config {
    /// Turns on the QUIC listener + HTTP/3 data plane when true.
    #[serde(default)]
    pub enabled: bool,
    /// Bind address for the QUIC endpoint (defaults to the TCP listener address).
    #[serde(default = "default_http3_bind_address")]
    pub bind_address: String,
    /// Bind port for QUIC datagrams (defaults to TCP listener port + 1).
    #[serde(default = "default_http3_bind_port")]
    pub bind_port: u16,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_http3_bind_address(),
            bind_port: default_http3_bind_port(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AltSvcStrategy {
    /// Strip Alt-Svc responses before sending to the client.
    Remove,
    /// Normalize Alt-Svc headers (default).
    Normalize,
    /// Rewrite Alt-Svc to redirect to another endpoint.
    Redirect,
}

impl Default for AltSvcStrategy {
    fn default() -> Self {
        AltSvcStrategy::Normalize
    }
}

fn default_profile_name() -> String {
    "firefox-windows".to_string()
}

fn default_http3_bind_address() -> String {
    default_bind_address()
}

fn default_http3_bind_port() -> u16 {
    default_bind_port().saturating_add(1)
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// Telemetry output: human-friendly stdout or structured JSON.
    #[serde(default)]
    pub mode: TelemetryMode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryMode {
    /// Print structured, readable logs to stdout.
    Stdout,
    /// Emit JSON objects for ingestion systems.
    Json,
}

impl Default for TelemetryMode {
    fn default() -> Self {
        TelemetryMode::Stdout
    }
}
