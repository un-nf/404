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
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{self, sign::CertifiedKey};

use crate::{config::{managed_cache_dir, managed_ca_cert_path, managed_keystore_blob_path, TlsConfig}, ensure_rustls_crypto_provider, keystore::build_keystore};

/// TlsProvider handles all the certificate magic that makes MITM interception work.
#[derive(Debug)]
pub struct TlsProvider {
    ca: CertificateAuthority,
    cache: CertificateCache,
}

const FALLBACK_SNI: &str = "static.local";

impl TlsProvider {
    /// Initializes the TlsProvider by loading or generating the CA certificate.
    ///
    /// First Run:
    /// If no CA exists at the configured paths, generates a new self-signed CA and writes
    /// Subsequent Runs:
    /// Loads the existing CA from disk using rcgen's PEM parsing utilities.
    pub async fn new(cfg: TlsConfig) -> Result<Self> {
        let ca = load_or_generate_ca(&cfg)?;

        Ok(Self {
            ca,
            cache: CertificateCache::new(),
        })
    }

    /// Returns a rustls CertifiedKey for the given server name (SNI hostname).
    ///
    /// If we've already issued a certificate for this hostname, return the cached Arc.
    pub fn certified_key(&self, server_name: &str) -> Result<Arc<CertifiedKey>> {
        let cache_key = normalize_sni(server_name);

        if let Some(hit) = self.cache.get(&cache_key) {
            tracing::trace!(sni = %cache_key, "using cached leaf certificate");
            return Ok(hit);
        }

        let leaf = self.ca.issue_leaf(&cache_key)?;
        let certified = build_certified_key(&leaf, self.ca.signer())?;

        let arc = Arc::new(certified);
        self.cache.insert(cache_key.clone(), arc.clone());
        tracing::debug!(sni = %cache_key, "issued new leaf certificate");
        Ok(arc)
    }

    /// Grabs cache metrics for telemetry or debugging.
    pub fn cache_metrics(&self) -> CacheMetrics {
        self.cache.metrics()
    }
}

pub(crate) fn initialize_ca_material(cfg: &TlsConfig) -> Result<()> {
    let _ = load_or_generate_ca(cfg)?;
    Ok(())
}

/// Lock-free, thread-safe storage for issued leaf certificates.

#[derive(Debug)]
struct CertificateCache {
    store: DashMap<String, CachedCert>,
    ttl: Duration,
    stats: CacheStats,
}

/// Wraps a cached certificate with its creation timestamp for TTL checks.
#[derive(Debug, Clone)]
struct CachedCert {
    key: Arc<CertifiedKey>,
    created_at: Instant,
}

impl CertificateCache {
    /// Creates an empty certificate cache with 24-hour TTL.
    fn new() -> Self {
        Self {
            store: DashMap::new(),
            ttl: Duration::from_secs(24 * 60 * 60), // 24 hours
            stats: CacheStats::new(),
        }
    }

    /// Grabs a cached certificate for the given hostname, respecting TTL.
    fn get(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        match self.store.get(host) {
            Some(entry) => {
                let cached = entry.value();
                if cached.created_at.elapsed() < self.ttl {
                    self.stats.record_hit();
                    Some(cached.key.clone())
                } else {
                    self.stats.record_regeneration();
                    tracing::debug!(host, age_secs = ?cached.created_at.elapsed().as_secs(), "certificate expired, regenerating");
                    None
                }
            }
            None => {
                self.stats.record_miss();
                None
            }
        }
    }

    /// Inserts a newly-issued cert into the cache with current timestamp.
    fn insert(&self, host: String, key: Arc<CertifiedKey>) {
        let cached = CachedCert {
            key,
            created_at: Instant::now(),
        };
        self.store.insert(host, cached);
    }

    fn metrics(&self) -> CacheMetrics {
        self.stats.snapshot()
    }
}

/// Wraps a self-signed root CA certificate and its private key.
struct CertificateAuthority {
    cert: Certificate,
}

const CA_KEY_NAME: &str = "ca_key";

// Custom Debug impl because rcgen::Certificate doesn't implement Debug.
impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CertificateAuthority {{ cert: <opaque rcgen::Certificate> }}"
        )
    }
}

impl CertificateAuthority {
    /// Loads existing CA from disk, or generates a fresh one if none exists.
    ///
    /// **Errors:**
    /// - Filesystem errors (permission denied, disk full, etc.)
    /// - PEM parsing errors (malformed CA files from manual editing)
    /// - rcgen errors (invalid cert params, unsupported key types)
    fn load_or_generate(cfg: &TlsConfig) -> Result<Self> {
        let ca_cert_path = managed_ca_cert_path();
        let keystore = build_keystore(&cfg.keystore, managed_keystore_blob_path().to_path_buf());
        let ca_cert_exists = ca_cert_path.exists();
        let ca_key_in_keystore = keystore.get_secret(CA_KEY_NAME)?;
        let ca_key_exists = ca_key_in_keystore.is_some();

        // If a cert already exists but no key is available, refuse to regenerate to avoid breaking trust.
        if ca_cert_exists != ca_key_exists {
            return Err(anyhow!(
                "managed CA state is inconsistent; remove stale CA artifacts and re-run CA setup"
            ));
        }

        if ca_cert_exists && ca_key_exists {
            let key_bytes = keystore
                .get_secret(CA_KEY_NAME)?
                .ok_or_else(|| anyhow!("CA certificate exists but no private key was recovered from secure storage"))?;
            let key_pem = String::from_utf8(key_bytes)?;

            let key_pair = rcgen::KeyPair::from_pem(&key_pem)?;

            let mut params = CertificateParams::default();
            params.alg = &PKCS_ECDSA_P256_SHA256;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.distinguished_name = dn_for("STATIC Local CA");
            params.key_pair = Some(key_pair);

            let cert = Certificate::from_params(params)?;
            Ok(Self { cert })
        } else {
            // Generate a new CA and persist to disk
            // Ensure parent directories exist (e.g., ~/.static_proxy/ca/)
            if let Some(parent) = ca_cert_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Generate self-signed CA certificate
            let cert = generate_ca();

            let key_pem = cert.serialize_private_key_pem();
            keystore.set_secret(CA_KEY_NAME, key_pem.as_bytes())?;

            // Verify the keystore actually retained the secret (fail fast instead of silently running without a key).
            match keystore.get_secret(CA_KEY_NAME)? {
                Some(_) => {
                    fs::write(ca_cert_path, cert.serialize_pem()?)?;
                    Ok(Self { cert })
                }
                None => Err(anyhow!("keystore did not persist CA key; aborting to avoid thumbprint drift")),
            }
        }
    }

    /// Issues a new leaf certificate for the given hostname, signed by this CA.
    fn issue_leaf(&self, server_name: &str) -> Result<Certificate> {
        // Start with default params for a server certificate (not a CA)
        let mut params = CertificateParams::new(vec![server_name.to_owned()]);

        // Use ECDSA P-256 to match the CA's algorithm
        params.alg = &PKCS_ECDSA_P256_SHA256;

        // Set the distinguished name (CN, O, etc.)
        params.distinguished_name = dn_for(server_name);

        // Generate the certificate with a new private key
        let cert = Certificate::from_params(params)?;
        Ok(cert)
    }

    /// Returns a reference to the rcgen Certificate (CA cert + private key).
    fn signer(&self) -> &Certificate {
        &self.cert
    }
}

fn load_or_generate_ca(cfg: &TlsConfig) -> Result<CertificateAuthority> {
    ensure_rustls_crypto_provider()?;

    let cache_dir = managed_cache_dir();

    if let Some(parent) = cache_dir.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(cache_dir)?;

    CertificateAuthority::load_or_generate(cfg)
}

/// Converts rcgen Certificate into rustls CertifiedKey (cert chain + signing key).
fn build_certified_key(leaf: &Certificate, signer: &Certificate) -> Result<CertifiedKey> {
    // Serialize leaf cert, signing it with the CA's private key
    let leaf_der = CertificateDer::from(leaf.serialize_der_with_signer(signer)?);

    // Serialize CA cert (public part only, no private key)
    let issuer_der = CertificateDer::from(signer.serialize_der()?);

    // Extract leaf's private key as PKCS#8 DER (not the CA's key!)
    let priv_key = PrivatePkcs8KeyDer::from(leaf.serialize_private_key_der());

    // Convert to rustls SigningKey using aws-lc-rs backend
    let signing_key = any_supported_type(&PrivateKeyDer::from(priv_key))?;

    // Build the chain: leaf first, then issuer (standard X.509 order)
    let chain = vec![leaf_der, issuer_der];

    Ok(CertifiedKey::new(chain, signing_key))
}

fn normalize_sni(server_name: &str) -> String {
    let trimmed = server_name.trim();
    if trimmed.is_empty() {
        FALLBACK_SNI.to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

#[derive(Debug, Clone)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub regenerations: u64,
}

#[derive(Debug)]
struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    regenerations: AtomicU64,
}

impl CacheStats {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            regenerations: AtomicU64::new(0),
        }
    }

    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    fn record_regeneration(&self) {
        self.regenerations.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> CacheMetrics {
        CacheMetrics {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            regenerations: self.regenerations.load(Ordering::Relaxed),
        }
    }
}

/// Generates a new self-signed Certificate Authority (CA) certificate.
fn generate_ca() -> Certificate {
    let mut params = CertificateParams::default();

    // Use ECDSA P-256 for performance and compatibility
    params.alg = &PKCS_ECDSA_P256_SHA256;

    // Mark this cert as a CA (can sign other certs)
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    // Set subject distinguished name (shows up in browser cert viewer)
    params.distinguished_name = dn_for("STATIC Local CA");

    // Generate the self-signed cert with a new private key
    Certificate::from_params(params).expect("failed to create CA")
}

/// Constructs an X.509 Distinguished Name (DN) for the given common name.
fn dn_for(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();

    // Set Common Name (shows up as "Issued to" in browsers)
    dn.push(DnType::CommonName, common_name);

    dn
}
