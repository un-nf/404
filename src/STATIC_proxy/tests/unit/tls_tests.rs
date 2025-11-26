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

use std::sync::Arc;

use serde_json::json;
use static_proxy::config::TlsConfig;
use static_proxy::tls::cert::TlsProvider;
use static_proxy::tls::fingerprint::{calculate_ja3, validate_profile};
use static_proxy::tls::handshake::ClientHello;
use static_proxy::tls::profiles::plan_from_profile;
use tempfile::tempdir;
use uuid::Uuid;

fn sample_hello() -> ClientHello {
    ClientHello {
        sni: Some("example.com".into()),
        version: 771,
        cipher_suites: vec![4865, 4866],
        extensions: vec![0, 10],
        elliptic_curves: vec![29, 23],
        ec_point_formats: vec![0],
    }
}

fn sample_tls_profile() -> serde_json::Value {
    json!({
        "tls": {
            "schema_version": 2,
            "versions": {
                "min": "tls12",
                "max": "tls13",
                "allow_tls12_fallback": true
            },
            "cipher_catalog": {
                "tls13": [
                    {"name": "TLS_AES_128_GCM_SHA256", "iana_id": 4865},
                    {"name": "TLS_AES_256_GCM_SHA384", "iana_id": 4866}
                ],
                "tls12": [
                    {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "iana_id": 49195},
                    {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "iana_id": 49196}
                ]
            },
            "hello_variants": [
                {
                    "id": "firefox-h2",
                    "weight": 1.0,
                    "alpn": ["h2"],
                    "supported_groups": ["x25519", "secp256r1"],
                    "cipher_order": {
                        "prefer_tls13": true
                    }
                }
            ]
        }
    })
}

#[test]
fn ja3_hash_matches_reference_value() {
    let hello = sample_hello();
    let hash = calculate_ja3(&hello).expect("hash is computed");
    assert_eq!(hash, "b57e61390dded8e2aaeff3ad22d89e36");
}

#[test]
fn validate_profile_rejects_mismatched_handshake() {
    let mut hello = sample_hello();
    let good_hash = calculate_ja3(&hello).expect("hash is computed");
    hello.cipher_suites.push(4867);
    assert!(!validate_profile(&hello, &good_hash).unwrap());
}

#[test]
fn tls_plan_from_profile_materializes_supported_values() {
    let profile = sample_tls_profile();
    let plan = plan_from_profile(&profile, Uuid::from_u128(42))
        .expect("profile parsed")
        .expect("plan produced");

    assert_eq!(plan.variant_id(), "firefox-h2");
    assert_eq!(
        plan.alpn_protocols(),
        &[b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert!(plan.cipher_suites().len() >= 2);
    assert!(plan.kx_groups().len() >= 2);
    assert!(plan
        .protocol_versions()
        .iter()
        .any(|version| std::ptr::eq(*version, &rustls::version::TLS12))); // TLS 1.2 fallback allowed
}

#[tokio::test]
async fn tls_provider_caches_normalized_sni_and_tracks_metrics() {
    let dir = tempdir().expect("tempdir");
    let cfg = TlsConfig {
        ca_cert_path: dir.path().join("static-ca.crt"),
        ca_key_path: dir.path().join("static-ca.key"),
        cache_dir: dir.path().join("cache"),
    };
    let provider = TlsProvider::new(cfg).await.expect("provider");

    let first = provider
        .certified_key("Example.COM")
        .expect("first issuance");
    let second = provider
        .certified_key("example.com")
        .expect("cache hit");

    assert!(Arc::ptr_eq(&first, &second));

    let metrics = provider.cache_metrics();
    assert_eq!(metrics.misses, 1, "first issuance increments miss counter");
    assert_eq!(metrics.hits, 1, "normalized SNI path reuses cache entry");
    assert_eq!(metrics.regenerations, 0);
}
