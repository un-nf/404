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

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use rustls::{crypto::aws_lc_rs, pki_types::ServerName};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{lookup_host, TcpStream},
    task,
    time::{sleep, timeout},
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::tls::profiles::TlsClientPlan;

/// Upstream client connector for establishing connections to origin servers.
pub struct UpstreamClient;

const DNS_CACHE_TTL_SECS: u64 = 60;
const DNS_MAX_ATTEMPTS: usize = 3;
const DNS_RETRY_BACKOFF_MS: u64 = 50;
const WSANO_DATA: i32 = 11004;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

static DNS_CACHE: Lazy<DashMap<String, CachedDnsEntry>> = Lazy::new(DashMap::new);

#[derive(Clone)]
struct CachedDnsEntry {
    expires_at: Instant,
    addrs: Vec<SocketAddr>,
}

impl UpstreamClient {
    /// Connects to the given host and port, returning a TLS stream.
    pub async fn connect(
        host: &str,
        port: u16,
        plan: Option<&TlsClientPlan>,
        alpn_override: Option<Vec<Vec<u8>>>,
    ) -> Result<TlsStream<TcpStream>> {
        let addr_label = format!("{}:{}", host, port);
        tracing::debug!(%addr_label, "dialing upstream");

        // Step 1: Resolve host to IPv4/IPv6 addresses with caching + fallback resolver.
        let addrs = resolve_upstream_addrs(host, port)
            .await
            .with_context(|| format!("failed to resolve {}", addr_label))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut tcp_stream = None;
        for addr in addrs.iter().copied() {
            tracing::debug!(%addr, "attempting upstream TCP connect");
            match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    tcp_stream = Some((stream, addr));
                    break;
                }
                Ok(Err(err)) => {
                    tracing::debug!(%addr, error = %err, "upstream TCP connect failed");
                    last_err = Some(err.into());
                }
                Err(_) => {
                    tracing::warn!(%addr, "upstream TCP connect timed out after {:?}", TCP_CONNECT_TIMEOUT);
                    last_err = Some(anyhow!(
                        "TCP connect to {addr} timed out after {:?}",
                        TCP_CONNECT_TIMEOUT
                    ));
                }
            }
        }

        let (stream, connected_addr) = tcp_stream.ok_or_else(|| {
            let err = last_err.unwrap_or_else(|| anyhow!(
                "DNS resolution for {} returned no addresses",
                addr_label
            ));
            anyhow!("failed to connect to {} via any resolved address: {err}", addr_label)
        })?;
        tracing::debug!(%connected_addr, "upstream TCP connected, starting TLS");

        // Step 2: Build TLS client config (validates server certs against system roots)
        let system_roots = || {
            let mut store = rustls::RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            store
        };

        let config = if let Some(plan) = plan {
            let mut provider = aws_lc_rs::default_provider();
            if !plan.cipher_suites().is_empty() {
                provider.cipher_suites = plan.owned_cipher_suites();
            }
            if !plan.kx_groups().is_empty() {
                provider.kx_groups = plan.kx_groups().to_vec();
            }

            let provider = Arc::new(provider);
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(plan.protocol_versions())
                .with_context(|| {
                    format!(
                        "variant {} has protocol versions incompatible with crypto provider",
                        plan.variant_id()
                    )
                })?;

            let mut cfg = builder
                .with_root_certificates(system_roots())
                .with_no_client_auth();

            if let Some(forced_alpn) = alpn_override.clone() {
                cfg.alpn_protocols = forced_alpn;
            } else if !plan.alpn_protocols().is_empty() {
                cfg.alpn_protocols = plan.alpn_protocols().to_vec();
            }

            tracing::debug!(variant = plan.variant_id(), "applied TLS client plan");
            cfg
        } else {
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(system_roots())
                .with_no_client_auth();
            cfg.alpn_protocols =
                alpn_override.unwrap_or_else(|| vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
            cfg
        };

        let connector = TlsConnector::from(Arc::new(config));

        // Step 3: Convert host to ServerName for SNI
        let server_name = ServerName::try_from(host.to_string())
            .with_context(|| format!("invalid hostname: {}", host))?;

        // Step 4: Perform TLS handshake
        let tls_future = connector.connect(server_name, stream);
        let tls_stream = match timeout(TLS_HANDSHAKE_TIMEOUT, tls_future).await {
            Ok(result) => result
                .with_context(|| format!("TLS handshake failed with {}", addr_label))?,
            Err(_) => {
                return Err(anyhow!(
                    "TLS handshake with {} timed out after {:?}",
                    addr_label,
                    TLS_HANDSHAKE_TIMEOUT
                ))
            }
        };

        tracing::debug!(addr = %addr_label, peer = %connected_addr, "upstream TLS handshake complete");

        Ok(tls_stream)
    }
}

async fn resolve_upstream_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let key = format!("{}:{}", host, port);
    let now = Instant::now();
    let mut expired = false;

    if let Some(entry) = DNS_CACHE.get(&key) {
        if entry.expires_at > now && !entry.addrs.is_empty() {
            tracing::trace!(target: "dns", %host, port, "dns cache hit");
            return Ok(entry.addrs.clone());
        }
        expired = entry.expires_at <= now;
    }

    if expired {
        DNS_CACHE.remove(&key);
    }

    let addrs = resolve_with_backoff(host, port).await?;
    if !addrs.is_empty() {
        DNS_CACHE.insert(
            key,
            CachedDnsEntry {
                expires_at: Instant::now() + Duration::from_secs(DNS_CACHE_TTL_SECS),
                addrs: addrs.clone(),
            },
        );
    }

    Ok(addrs)
}

async fn resolve_with_backoff(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=DNS_MAX_ATTEMPTS {
        match lookup_host((host, port)).await {
            Ok(iter) => {
                let addrs: Vec<SocketAddr> = iter.collect();
                if !addrs.is_empty() {
                    tracing::trace!(target: "dns", %host, port, attempt, "tokio resolver success");
                    return Ok(addrs);
                }
                last_err = Some(anyhow!("resolver returned no addresses for {}:{}", host, port));
            }
            Err(err) => {
                if is_wsano_data(&err) {
                    tracing::debug!(target: "dns", %host, port, "tokio resolver hit WSANO_DATA; using system resolver");
                    return resolve_with_system(host, port).await;
                }
                let err_msg = err.to_string();
                tracing::warn!(target: "dns", %host, port, attempt, error = %err_msg, "tokio resolver error");
                last_err = Some(err.into());
            }
        }

        if attempt < DNS_MAX_ATTEMPTS {
            let delay = Duration::from_millis(DNS_RETRY_BACKOFF_MS * attempt as u64);
            sleep(delay).await;
        }
    }

    tracing::warn!(target: "dns", %host, port, "tokio resolver exhausted retries; falling back to system resolver");
    match resolve_with_system(host, port).await {
        Ok(addrs) => Ok(addrs),
        Err(fallback_err) => Err(last_err.unwrap_or(fallback_err)),
    }
}

async fn resolve_with_system(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let host_owned = host.to_string();
    task::spawn_blocking(move || {
        (&host_owned[..], port)
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>())
            .map_err(|err| anyhow!(err))
    })
    .await
    .context("system resolver task failed")?
}

fn is_wsano_data(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(WSANO_DATA))
}
