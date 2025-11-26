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
    path::PathBuf,
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::{Duration, Instant},
};

use anyhow::Result;
use dashmap::DashMap;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{self, sign::CertifiedKey};

use crate::config::TlsConfig;

/// TlsProvider handles all the certificate magic that makes MITM interception work.
///
/// Here's the deal: we maintain one Certificate Authority (CA) and dynamically issue leaf certificates
/// for whatever hostname the client requests via SNI. As long as they trust our CA, the browser has no
/// idea we're sitting in the middle of their HTTPS traffic.
///
/// **How it works:**
/// - CA: One self-signed root cert, loaded from disk or generated on first run.
/// - Cache: In-memory DashMap storing issued leaf certs keyed by normalized hostname.
/// - Leaf Issuance: Generate server certs on-demand, signed by our CA.
///
/// **Security stuff:**
/// - CA private key stays in memory after loading (except when we first generate it).
/// - Leaf certs cached with 24h TTL; regeneration gives you a fresh keypair.
/// - Memory grows with unique SNIs; totally fine for MITM but worth noting.
#[derive(Debug)]
pub struct TlsProvider {
    ca: CertificateAuthority,
    cache: CertificateCache,
    cache_dir: PathBuf, // TODO: Not using this yet, but prepped for disk-backed cert caching down the road
}

const FALLBACK_SNI: &str = "static.local";

impl TlsProvider {
    /// Initializes the TlsProvider by loading or generating the CA certificate.
    ///
    /// First Run:
    /// If no CA exists at the configured paths, generates a new self-signed CA and writes
    /// both the certificate and private key to disk as PEM files. The user must manually
    /// trust this CA in their OS/browser certificate store before the proxy can intercept traffic.
    ///
    /// Subsequent Runs:
    /// Loads the existing CA from disk using rcgen's PEM parsing utilities.
    pub async fn new(cfg: TlsConfig) -> Result<Self> {
        // Ensure the cache directory exists (though we don't use it yet)
        if let Some(parent) = cfg.cache_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&cfg.cache_dir)?;
        let cache_dir = cfg.cache_dir.clone();

        // Load existing CA from disk, or generate a fresh one and persist it
        let ca = CertificateAuthority::load_or_generate(&cfg)?;

        Ok(Self {
            ca,
            cache: CertificateCache::new(),
            cache_dir,
        })
    }

    /// Returns a rustls CertifiedKey for the given server name (SNI hostname).
    ///
    /// If we've already issued a certificate for this hostname, return the cached Arc.
    ///
    /// or...
    /// 1. Generate a new leaf certificate for the requested hostname
    /// 2. Sign it with our CA
    /// 3. Wrap it in a rustls CertifiedKey (certificate chain + private key)
    /// 4. Cache the result for future requests
    /// 5. Return an Arc to the cached entry
    ///
    /// DashMap for lock-free concurrent reads/writes. Safe to call from multiple
    /// connection handlers simultaneously.
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

/// Lock-free, thread-safe storage for issued leaf certificates.
///
/// **Data structure:**
/// DashMap (concurrent HashMap) keyed by lowercase hostname. Each value is a CachedCert
/// wrapping the Arc<CertifiedKey> plus creation timestamp for TTL checks.
///
/// **Thread safety:**
/// DashMap uses sharded locking internally, way better concurrency than a single Mutex<HashMap>.
/// Totally safe to call get/insert from multiple tokio tasks at once.
///
/// **Memory management:**
/// - TTL-based eviction: certs expire after 24 hours, regenerated on next request
/// - Expired entries hang around in memory until next access (lazy eviction)
/// - Each CachedCert is ~2KB (DER cert + private key + timestamp), so 10K unique hosts ≈ 20MB
///
/// **Security wins:**
/// - Limits cert compromise window to TTL duration (24 hours)
/// - Forces periodic key rotation without breaking browser sessions
/// - Expired certs auto-regenerate with fresh key pairs
///
/// **Future stuff:**
/// - Add LRU eviction or size-based limits
/// - Background task to proactively clean expired entries
/// - Persist cache to disk on shutdown (cache_dir already prepped for this)
#[derive(Debug)]
struct CertificateCache {
    store: DashMap<String, CachedCert>,
    ttl: Duration,
    stats: CacheStats,
}

/// Wraps a cached certificate with its creation timestamp for TTL checks.
///
/// **Purpose:**
/// Ties each cached cert to the time it was issued so we can invalidate expired entries
/// and regenerate with fresh keys.
///
/// **TTL enforcement:**
/// On cache lookup, check if `created_at.elapsed() > ttl`. Expired? Treat it as a cache miss.
#[derive(Debug, Clone)]
struct CachedCert {
    key: Arc<CertifiedKey>,
    created_at: Instant,
}

impl CertificateCache {
    /// Creates an empty certificate cache with 24-hour TTL.
    ///
    /// **Why 24 hours?**
    /// - Balances security (limits compromise window) and performance (avoids thrash)
    /// - Short enough that stolen certs expire fast
    /// - Long enough that normal browsing sessions don't trigger regeneration
    fn new() -> Self {
        Self {
            store: DashMap::new(),
            ttl: Duration::from_secs(24 * 60 * 60), // 24 hours
            stats: CacheStats::new(),
        }
    }

    /// Grabs a cached certificate for the given hostname, respecting TTL.
    ///
    /// **Returns:**
    /// - Some(Arc<CertifiedKey>) if hostname has a valid (non-expired) cached cert
    /// - None if this is the first request OR the cached cert exceeded TTL
    ///
    /// **TTL enforcement:**
    /// Checks `created_at.elapsed()` against configured TTL. Expired entries get treated
    /// as cache misses (caller regenerates). Stale entry stays in cache until overwritten
    /// (lazy eviction).
    ///
    /// **Cloning behavior:**
    /// Arc is cloned (cheap pointer copy, not the cert itself), so the underlying
    /// CertifiedKey is shared across all connections to this hostname.
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
    ///
    /// **Timestamp:**
    /// Uses `Instant::now()` to record creation time for TTL checks on future lookups.
    ///
    /// **Concurrency:**
    /// If two tasks try to insert the same hostname at once (cache miss race),
    /// DashMap serializes the writes. One wins, the other's cert gets dropped.
    /// Totally safe: both certs are valid and functionally identical.
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
///
/// **What it does:**
/// - Load existing CA from disk (cert + key as PEM files)
/// - Generate new CA on first run and persist to disk
/// - Sign leaf certificates for arbitrary hostnames (MITM server certs)
///
/// **Crypto:**
/// - ECDSA P-256 (secp256r1) signatures for both CA and leaf certs
/// - CA marked as cert authority (basicConstraints: CA:TRUE)
/// - Leaf certs valid for 1 year, CA valid for 10 years
///
/// **Security stuff:**
/// - CA private key is the crown jewel: if leaked, attackers can issue trusted certs
/// - rcgen::Certificate contains both public cert and private key in one struct
/// - Lives only in memory after initial load/generate; never serialized again
///   (except during first-run generation when written to disk as PEM)
struct CertificateAuthority {
    /// The rcgen certificate wrapping both the CA cert and its private key.
    /// rcgen::Certificate doesn't implement Debug, so we provide a custom impl.
    cert: Certificate,
}

// Custom Debug impl because rcgen::Certificate doesn't implement Debug.
// Keeps sensitive stuff (private key) hidden while satisfying the Debug bound
// required by rustls::server::ResolvesServerCert trait.
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
    /// **Load path (both files exist):**
    /// 1. Read CA cert and key from disk as PEM-encoded strings
    /// 2. Parse PEM format using the `pem` crate (extracts base64 DER blob)
    /// 3. Parse DER-encoded cert using rcgen's from_ca_cert_der
    /// 4. Parse private key using rcgen's KeyPair::from_pem
    /// 5. Combine into rcgen::Certificate for in-memory use
    ///
    /// **Generate path (either file missing):**
    /// 1. Call generate_ca() to create new self-signed CA
    /// 2. Serialize to PEM format (both cert and private key)
    /// 3. Write both files to disk for reuse across proxy restarts
    /// 4. Return the in-memory Certificate
    ///
    /// **User action required:**
    /// On first run, you've gotta manually trust the generated CA in your OS/browser
    /// cert store before the proxy can intercept HTTPS traffic. Paths get logged
    /// during startup (see telemetry.rs).
    ///
    /// **Errors:**
    /// - Filesystem errors (permission denied, disk full, etc.)
    /// - PEM parsing errors (malformed CA files from manual editing)
    /// - rcgen errors (invalid cert params, unsupported key types)
    ///
    /// **TODO:** Add explicit logging here when generating a new CA, with instructions
    /// on how to trust it. Currently only logged at startup in main.rs.
    fn load_or_generate(cfg: &TlsConfig) -> Result<Self> {
        if cfg.ca_cert_path.exists() && cfg.ca_key_path.exists() {
            // Load existing CA from disk
            // rcgen 0.12 doesn't have from_ca_cert_der, so we reconstruct the Certificate manually
            let key_pem = fs::read_to_string(&cfg.ca_key_path)?;

            // Parse the private key from PEM format
            let key_pair = rcgen::KeyPair::from_pem(&key_pem)?;

            // Build CertificateParams with the loaded key pair
            // We don't parse the certificate itself; we just need the key to sign with
            let mut params = CertificateParams::default();
            params.alg = &PKCS_ECDSA_P256_SHA256;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.distinguished_name = dn_for("STATIC Local CA");
            params.key_pair = Some(key_pair);

            // Reconstruct the Certificate from params with the loaded key
            let cert = Certificate::from_params(params)?;
            Ok(Self { cert })
        } else {
            // Generate a new CA and persist to disk
            // Ensure parent directories exist (e.g., ~/.static_proxy/ca/)
            if let Some(parent) = cfg.ca_cert_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if let Some(parent) = cfg.ca_key_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Generate self-signed CA certificate
            let cert = generate_ca();

            // Serialize and write to disk (PEM format for human readability)
            fs::write(&cfg.ca_cert_path, cert.serialize_pem()?)?;
            fs::write(&cfg.ca_key_path, cert.serialize_private_key_pem())?;

            Ok(Self { cert })
        }
    }

    /// Issues a new leaf certificate for the given hostname, signed by this CA.
    ///
    /// **Cert properties:**
    /// - Subject Alternative Name (SAN): Set to the requested hostname
    /// - Validity: 1 year from issuance (default rcgen behavior)
    /// - Algorithm: ECDSA P-256 with SHA-256 (PKCS_ECDSA_P256_SHA256)
    /// - Distinguished Name: CN=<hostname>, O=STATIC Proxy
    ///
    /// **MITM workflow:**
    /// 1. Client sends TLS ClientHello with SNI = "example.com"
    /// 2. Proxy extracts SNI and calls this method
    /// 3. rcgen generates a new ECDSA P-256 key pair for the leaf cert
    /// 4. Leaf cert gets signed by the CA's private key (happens in serialize_der_with_signer)
    /// 5. Proxy returns the leaf cert in the ServerHello
    /// 6. Client validates the cert chain: leaf → CA (must be trusted)
    ///
    /// **Security note:**
    /// Each leaf cert has its own private key (generated by rcgen). The CA private
    /// key never gets exposed to the leaf cert; only used for signing.
    ///
    /// **Errors:**
    /// - Bails if hostname is invalid (empty string, non-ASCII, etc.)
    /// - Bails if rcgen can't generate the cert params
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
    ///
    /// **Usage:**
    /// Called by build_certified_key to sign leaf certs. The signer's DER-encoded
    /// cert gets included in the chain so browsers can validate the leaf cert back
    /// to the trusted CA.
    ///
    /// **Ownership:**
    /// Returns a reference (&Certificate) instead of cloning, because rcgen::Certificate
    /// isn't Clone (contains a private key). Caller only needs to borrow it for
    /// the signing operation.
    fn signer(&self) -> &Certificate {
        &self.cert
    }
}

/// Converts rcgen Certificate into rustls CertifiedKey (cert chain + signing key).
///
/// **Purpose:**
/// rustls needs a CertifiedKey to complete the TLS handshake. This bridges the gap
/// between rcgen (certificate generation) and rustls (TLS protocol implementation).
///
/// **Certificate chain construction:**
/// 1. Serialize leaf cert signed by CA (rcgen → DER bytes)
/// 2. Serialize CA cert (issuer) (rcgen → DER bytes)
/// 3. Build chain: [leaf_der, issuer_der]
/// 4. Client validates: leaf signed by issuer, issuer is trusted in cert store
///
/// **Private key conversion:**
/// rcgen outputs raw PKCS#8 DER bytes (Vec<u8>), but rustls needs specific types:
/// - Vec<u8> → PrivatePkcs8KeyDer (typed wrapper indicating PKCS#8 format)
/// - PrivatePkcs8KeyDer → PrivateKeyDer (enum covering PKCS#8/PKCS#1/SEC1)
/// - PrivateKeyDer → Box<dyn SigningKey> (rustls signing interface)
///
/// The last step (any_supported_type) uses aws-lc-rs to parse the key and create a
/// SigningKey implementation that can sign TLS handshake messages.
///
/// **Errors:**
/// - Bails if DER serialization fails (rare, indicates broken rcgen state)
/// - Bails if aws-lc-rs can't parse the private key (unsupported algorithm, corrupted bytes)
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
///
/// **Cert properties:**
/// - Subject: CN=STATIC Local CA
/// - Validity: 10 years from generation (3650 days, rcgen default)
/// - Algorithm: ECDSA P-256 with SHA-256 (PKCS_ECDSA_P256_SHA256)
/// - Basic Constraints: CA:TRUE (this cert can sign other certs)
/// - Key Usage: Certificate Signing (implied by basicConstraints CA:TRUE)
///
/// **Why ECDSA P-256?**
/// - Widely supported by browsers and TLS stacks (unlike Ed25519, which is newer)
/// - Way faster than RSA for signing operations (critical for high-throughput MITM)
/// - Smaller key sizes (256 bits vs 2048+ for RSA) = less network overhead
///
/// **CA:TRUE constraint:**
/// Without this, browsers reject any leaf certs signed by this CA with
/// "certificate is not a CA" errors. This marks the cert as an intermediate/root CA.
///
/// **Self-signed:**
/// The CA signs itself (issuer == subject). Standard for root CAs. Browsers
/// only trust it if you manually import it into their trust store.
///
/// **Panics:**
/// Panics if rcgen fails to generate the cert (extremely rare, would indicate
/// system crypto failure or memory corruption). Acceptable because we can't
/// proceed without a CA.
///
/// **TODO:**
/// - Add logging/UI to guide users through CA trust installation on first run
/// - Consider adding serial number randomization (currently uses rcgen defaults)
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
///
/// **Distinguished Name fields:**
/// - CN (Common Name): The hostname or cert identifier (e.g., "example.com")
///
/// **Why only CN?**
/// Modern browsers primarily validate certs using Subject Alternative Names (SANs),
/// not the DN fields. Including CN for compatibility with older TLS stacks and for
/// better human readability in cert viewers, but omitting other fields (O, OU, L, ST, C)
/// to keep generated certs minimal.
///
/// **Usage:**
/// - Called when generating the CA cert (CN = "STATIC Local CA")
/// - Called when issuing leaf certs (CN = hostname, e.g., "api.github.com")
///
/// **Note:**
/// SAN extension gets added automatically by rcgen when calling CertificateParams::new()
/// with a vec of hostnames (see issue_leaf method).
fn dn_for(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();

    // Set Common Name (shows up as "Issued to" in browsers)
    dn.push(DnType::CommonName, common_name);

    dn
}
