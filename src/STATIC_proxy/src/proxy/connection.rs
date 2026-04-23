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

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::future::poll_fn;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use h2::{ext::Protocol as H2Protocol, server::{Builder as H2ServerBuilder, SendResponse}, Reason, SendStream};
use http::header::{
    HeaderName, HeaderValue, CACHE_CONTROL, CONTENT_TYPE, ETAG, EXPIRES, LAST_MODIFIED, PRAGMA,
};
use http_body::Body as _;
use rustls::{server::ClientHello, server::ResolvesServerCert, ClientConfig, RootCertStore, ServerConfig};
use rustls::{pki_types::ServerName, sign::CertifiedKey, ServerConnection};
use tokio::io::{split, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, WriteHalf};
use tokio::time::{timeout, Duration};
use tokio::net::TcpStream;
use tokio_rustls::{server as rustls_server, TlsAcceptor, TlsConnector};

use crate::{
    assets::ScriptBundle,
    config::BodyLimitsConfig,
    proxy::{
        fetcher::{plan_supports_h2_upstream, OriginFetcher, OriginTarget, UpstreamMode},
        flow::BodyBuffer, flow::Flow, flow::RequestParts, flow::ResponseParts,
        stages::StagePipeline,
    },
    telemetry::TelemetrySink,
    tls::{
        cert::TlsProvider,
        profiles::{plan_attempts_from_profile_with_alpn, plan_from_profile, TlsClientPlan}
    },
};

/// Tokio-friendly alias for the client-facing TLS stream (rustls over TCP).
type ClientTlsStream = rustls_server::TlsStream<TcpStream>;

const FALLBACK_SNI: &str = "static.local";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HTTP_HEAD_BYTES: usize = 64 * 1024;
const CLIENT_H2_MAX_CONCURRENT_STREAMS: u32 = 256;
const CLIENT_H2_INITIAL_WINDOW_SIZE: u32 = 1_048_576;
const CLIENT_H2_INITIAL_CONNECTION_WINDOW_SIZE: u32 = 4_194_304;
const H2_SEND_CHUNK_SIZE: usize = 16 * 1024;
const RUNTIME_ASSET_PATH: &str = "/__static/runtime.js";

/// Detects whether the connection is HTTP or HTTPS by peeking at the first byte.
async fn detect_protocol(socket: &TcpStream) -> Result<Protocol> {
    let mut buf = [0u8; 1];
    socket.peek(&mut buf).await?;

    match buf[0] {
        0x16 => Ok(Protocol::Tls), // TLS Handshake
        b'G' | b'P' | b'H' | b'D' | b'O' | b'C' | b'T' => Ok(Protocol::Http), // HTTP methods
        _ => Ok(Protocol::Unknown),
    }
}

#[derive(Debug, PartialEq)]
enum Protocol {
    Tls,
    Http,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpRequestKind {
    Connect,
    Plain,
}

/// Handles a single client connection from TCP accept through TLS termination, protocol routing,
pub async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    body_limits: BodyLimitsConfig,
    tls: Arc<TlsProvider>,
    fetcher: Arc<dyn OriginFetcher>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    _http3_enabled: bool,
) -> Result<()> {

    let protocol = detect_protocol(&socket).await?;

    let target_host = match protocol {
        Protocol::Http => {
            match detect_http_request_kind(&socket).await? {
                HttpRequestKind::Connect => {

                    tracing::debug!(%peer, "HTTP CONNECT detected, establishing tunnel");
                    match handle_connect_tunnel(&mut socket).await {
                        Ok(host) => {
                            tracing::info!(%peer, target = %host, "CONNECT tunnel established");
                            Some(host)
                        }
                        Err(e) => {
                            tracing::error!(%peer, error = %e, "CONNECT tunnel failed");
                            return Err(e);
                        }
                    }
                }
                HttpRequestKind::Plain => {
                    tracing::debug!(%peer, "plain HTTP proxy request detected");
                    return handle_plain_http_session(
                        socket,
                        peer,
                        body_limits,
                        fetcher,
                        stages,
                        telemetry,
                    )
                    .await;
                }
            }
        }
        Protocol::Unknown => {
            tracing::warn!(%peer, "rejecting connection with unknown protocol");
            return Err(anyhow::anyhow!("unknown protocol"));
        }
        Protocol::Tls => {

            tracing::debug!(%peer, "direct TLS connection detected");
            None
        }
    };

    tracing::debug!(%peer, "starting TLS handshake");

    let fallback_sni = handshake_fallback_sni(target_host.as_deref());
    let handshake = timeout(HANDSHAKE_TIMEOUT, accept_tls_session(socket, tls, fallback_sni)).await;
    let (client_tls, sni) = match handshake {
        Ok(result) => result.with_context(|| format!("TLS handshake failed for {peer}"))?,
        Err(_) => {
            return Err(anyhow!(
                "TLS handshake timed out for {peer} after {:?}",
                HANDSHAKE_TIMEOUT
            ))
        }
    };

    tracing::info!(%peer, sni = sni.as_deref().unwrap_or("<none>"), "client handshake complete");

    let negotiated_alpn = client_tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|proto| proto.to_vec());

    match negotiated_alpn.as_deref() {
        Some(b"h2") => {
            tracing::debug!(%peer, "negotiated HTTP/2 with client");
            handle_http2_session(
                client_tls,
                peer,
                body_limits,
                fetcher,
                stages,
                telemetry,
                sni,
                target_host,
            )
            .await
        }
        _ => {
            tracing::debug!(%peer, "falling back to HTTP/1.1");
            handle_http1_session(
                client_tls,
                peer,
                body_limits,
                fetcher,
                stages,
                telemetry,
                sni,
                target_host,
            )
            .await
        }
    }
}

async fn detect_http_request_kind(socket: &TcpStream) -> Result<HttpRequestKind> {
    let mut buf = [0u8; 4096];
    let read = socket
        .peek(&mut buf)
        .await
        .context("failed to peek HTTP request line")?;
    if read == 0 {
        anyhow::bail!("client closed connection before sending HTTP request line");
    }

    let method = String::from_utf8_lossy(&buf[..read])
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();

    if method == "CONNECT" {
        Ok(HttpRequestKind::Connect)
    } else {
        Ok(HttpRequestKind::Plain)
    }
}

/// Handles HTTP CONNECT tunnel establishment for browser proxy connections.
async fn handle_connect_tunnel(socket: &mut TcpStream) -> Result<String> {
    let mut reader = BufReader::new(socket);
    let mut request_line = String::new();

    reader
        .read_line(&mut request_line)
        .await
        .context("failed to read CONNECT request line")?;

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();

    if parts.len() < 2 || parts[0] != "CONNECT" {
        anyhow::bail!("invalid CONNECT request: {}", request_line);
    }

    let target = parts[1].to_string();

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    let socket = reader.into_inner();
    socket
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("failed to send 200 Connection Established")?;

    tracing::debug!(target = %target, "sent 200 Connection Established");
    Ok(target)
}

/// Builds a rustls ServerConfig that dynamically issues certificates per-SNI.
fn build_server_config(tls: Arc<TlsProvider>, fallback_sni: Option<String>) -> ServerConfig {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OnDemandCertResolver::new(tls, fallback_sni)));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// Orchestrates the HTTP/1.1 data path once TLS is terminated.
async fn handle_http1_session(

    mut client_stream: ClientTlsStream,
    peer: SocketAddr,
    body_limits: BodyLimitsConfig,
    fetcher: Arc<dyn OriginFetcher>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    sni: Option<String>,
    target_host: Option<String>,

) -> Result<()> {

    let parsed = parse_http_request(&mut client_stream, body_limits.max_request_body_bytes).await?;
    tracing::debug!(%peer, method = %parsed.request.method, uri = %parsed.request.uri, "parsed HTTP/1.1 request");

    let mut flow = Flow::new(parsed.request);
    flow.metadata.tls_sni = sni.clone();
    flow.metadata.connect_target = target_host;
    flow.metadata.client_protocol = Some("http/1.1".to_string());
    flow.metadata.buffering_mode = Some("buffered-http1".to_string());

    if is_proxy_runtime_asset_request(&flow.request) {
        flow.metadata.request_protocol = Some("proxy-runtime-asset".to_string());
        flow.metadata.upstream_protocol = Some("local".to_string());
        flow.metadata.buffering_mode = Some("local-asset".to_string());
        flow.response = Some(build_proxy_runtime_asset_response(flow.request.version, &flow.request.method)?);
        emit_flow_telemetry(&telemetry, &flow, &sni, peer);
        let response = flow.response.as_ref().context("runtime asset response missing")?;
        send_response_to_client(&mut client_stream, response).await?;
        return Ok(());
    }

    stages.process_request(&mut flow).await?;

    let tls_plan = http1_tls_plan(&flow.metadata.fingerprint_config, flow.id)?;
    if let Some(plan) = &tls_plan {
        flow.metadata.tls_variant_id = Some(plan.variant_id().to_string());
        if !plan_supports_h2_upstream(plan) {
            flow.metadata
                .transport_notes
                .push("upstream-http1-only-variant".to_string());
        }
        tracing::debug!(%peer, variant = plan.variant_id(), "selected TLS hello variant");
    }

    if is_websocket_upgrade_request(&flow.request) {
        flow.metadata.websocket_tunnel = true;
        flow.metadata.request_protocol = Some("websocket".to_string());
        flow.metadata.buffering_mode = Some("raw-websocket-tunnel".to_string());
        flow.metadata.transport_notes.push("http1-websocket-upgrade".to_string());
        tracing::debug!(%peer, uri = %flow.request.uri, "forwarding websocket upgrade over raw upstream TLS");
        return tunnel_websocket_upgrade(
            &mut client_stream,
            parsed.buffered_tail,
            &mut flow,
            peer,
            &telemetry,
            &sni,
        )
        .await;
    }

    let (host, port) = resolve_upstream_target(&flow);
    tracing::debug!(%peer, %host, port, "connecting to upstream (HTTP/1.1)");
    let origin = fetcher
        .fetch(
            &flow,
            &OriginTarget::new(host, port),
            tls_plan,
            UpstreamMode::Http1Only,
        )
        .await?;
    tracing::debug!(%peer, status = %origin.response.status, "received upstream response");
    flow.metadata.upstream_protocol = Some(origin.upstream_protocol);
    flow.response = Some(origin.response);

    stages.process_response_headers(&mut flow).await?;
    stages.process_response_body(&mut flow).await?;
    stages.finalize_response(&mut flow).await?;

    if let Some(response) = flow.response.as_mut() {
        normalize_bootstrap_asset_response(&flow.request, response);
        enforce_content_length(response)?;
        response.version = flow.request.version;
    }

    emit_flow_telemetry(&telemetry, &flow, &sni, peer);

    let response = flow
        .response
        .as_ref()
        .context("response missing after pipeline execution")?;
    send_response_to_client(&mut client_stream, response).await?;
    tracing::debug!(%peer, "response delivered to client");
    Ok(())
}

async fn handle_plain_http_session(
    mut client_stream: TcpStream,
    peer: SocketAddr,
    body_limits: BodyLimitsConfig,
    fetcher: Arc<dyn OriginFetcher>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
) -> Result<()> {
    let parsed = parse_http_request(&mut client_stream, body_limits.max_request_body_bytes).await?;
    tracing::debug!(%peer, method = %parsed.request.method, uri = %parsed.request.uri, "parsed plain HTTP request");

    let mut flow = Flow::new(parsed.request);
    flow.metadata.client_protocol = Some("http/1.1".to_string());
    flow.metadata.request_protocol = Some("http-proxy".to_string());
    flow.metadata.buffering_mode = Some("buffered-http1".to_string());

    if is_proxy_runtime_asset_request(&flow.request) {
        flow.metadata.upstream_protocol = Some("local".to_string());
        flow.metadata.buffering_mode = Some("local-asset".to_string());
        flow.response = Some(build_proxy_runtime_asset_response(flow.request.version, &flow.request.method)?);
        emit_flow_telemetry(&telemetry, &flow, &None, peer);
        let response = flow.response.as_ref().context("runtime asset response missing")?;
        send_response_to_client(&mut client_stream, response).await?;
        return Ok(());
    }

    stages.process_request(&mut flow).await?;

    let (host, port) = resolve_upstream_target(&flow);
    tracing::debug!(%peer, %host, port, "connecting to upstream (plain HTTP/1.1)");
    let origin = fetcher
        .fetch(
            &flow,
            &OriginTarget::new(host, port),
            None,
            UpstreamMode::Http1Only,
        )
        .await?;
    tracing::debug!(%peer, status = %origin.response.status, "received upstream response");
    flow.metadata.upstream_protocol = Some(origin.upstream_protocol);
    flow.response = Some(origin.response);

    stages.process_response_headers(&mut flow).await?;
    stages.process_response_body(&mut flow).await?;
    stages.finalize_response(&mut flow).await?;

    if let Some(response) = flow.response.as_mut() {
        normalize_bootstrap_asset_response(&flow.request, response);
        enforce_content_length(response)?;
        response.version = flow.request.version;
    }

    emit_flow_telemetry(&telemetry, &flow, &None, peer);

    let response = flow
        .response
        .as_ref()
        .context("response missing after pipeline execution")?;
    send_response_to_client(&mut client_stream, response).await?;
    tracing::debug!(%peer, "plain HTTP response delivered to client");
    Ok(())
}

async fn tunnel_websocket_upgrade(
    client_stream: &mut ClientTlsStream,
    client_buffered_tail: Vec<u8>,
    flow: &mut Flow,
    peer: SocketAddr,
    telemetry: &TelemetrySink,
    sni: &Option<String>,
) -> Result<()> {
    let (host, port) = resolve_upstream_target(flow);
    let tcp_stream = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("failed to connect websocket upstream {host}:{port}"))?;
    let connector = build_upstream_tls_connector()?;
    let server_name = ServerName::try_from(host.clone())
        .with_context(|| format!("invalid upstream TLS server name: {host}"))?;
    let mut upstream_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .with_context(|| format!("failed to establish upstream TLS for websocket {host}:{port}"))?;

    send_upstream_http1_request(&mut upstream_stream, &flow.request, &host, port).await?;

    let (response_head, upstream_buffered_tail) = read_http_head(&mut upstream_stream, MAX_HTTP_HEAD_BYTES)
        .await
        .context("failed to read websocket upgrade response head")?;
    let response = parse_http_response_head(&response_head)?;

    flow.metadata.upstream_protocol = Some("http/1.1".to_string());
    flow.response = Some(response);

    client_stream
        .write_all(&response_head)
        .await
        .context("failed to forward websocket response head to client")?;
    if !upstream_buffered_tail.is_empty() {
        client_stream
            .write_all(&upstream_buffered_tail)
            .await
            .context("failed to forward buffered websocket response bytes to client")?;
    }
    client_stream.flush().await?;

    let status = flow
        .response
        .as_ref()
        .map(|response| response.status)
        .context("websocket upgrade response missing after parse")?;

    if status == http::StatusCode::SWITCHING_PROTOCOLS {
        if !client_buffered_tail.is_empty() {
            upstream_stream
                .write_all(&client_buffered_tail)
                .await
                .context("failed to forward buffered websocket client bytes upstream")?;
            upstream_stream.flush().await?;
        }

        emit_flow_telemetry(telemetry, flow, sni, peer);
        super::pipeline::proxy_data(client_stream, &mut upstream_stream).await?;
        return Ok(());
    }

    emit_flow_telemetry(telemetry, flow, sni, peer);
    tokio::io::copy(&mut upstream_stream, client_stream)
        .await
        .context("failed to stream non-upgrade websocket response body to client")?;
    client_stream.flush().await?;
    Ok(())
}

/// Terminates the client-facing HTTP/2 connection and spins up per-stream tasks.
async fn handle_http2_session(
    client_stream: ClientTlsStream,
    peer: SocketAddr,
    body_limits: BodyLimitsConfig,
    fetcher: Arc<dyn OriginFetcher>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    sni: Option<String>,
    target_host: Option<String>,
) -> Result<()> {
    let mut builder = H2ServerBuilder::new();
    builder
        .max_concurrent_streams(CLIENT_H2_MAX_CONCURRENT_STREAMS)
        .initial_window_size(CLIENT_H2_INITIAL_WINDOW_SIZE)
        .initial_connection_window_size(CLIENT_H2_INITIAL_CONNECTION_WINDOW_SIZE)
        .enable_connect_protocol();

    let mut connection = match builder.handshake(client_stream).await {
        Ok(connection) => connection,
        Err(err) => {
            if is_benign_client_h2_shutdown(&err.to_string()) {
                tracing::debug!(%peer, error = %err, "client closed HTTP/2 session before handshake completed");
                return Ok(());
            }
            return Err(err).context("failed to negotiate HTTP/2 with client");
        }
    };
    while let Some(result) = connection.accept().await {
        let (request, respond) = match result {
            Ok(next) => next,
            Err(err) => {
                if is_benign_client_h2_shutdown(&err.to_string()) {
                    tracing::debug!(%peer, error = %err, "client closed HTTP/2 session without close_notify");
                    break;
                }
                return Err(err.into());
            }
        };
        let fetcher_clone = fetcher.clone();
        let stages_clone = stages.clone();
        let telemetry_clone = telemetry.clone();
        let sni_clone = sni.clone();
        let target_clone = target_host.clone();
        let body_limits_clone = body_limits.clone();

        tokio::spawn(async move {
            if let Err(err) = process_http2_stream(
                request,
                respond,
            body_limits_clone,
                fetcher_clone,
                stages_clone,
                telemetry_clone,
                peer,
                sni_clone,
                target_clone,
            )
            .await
            {
                tracing::debug!(%peer, "HTTP/2 stream task ended with error: {err:?}");
            }
        });
    }

    Ok(())
}

fn is_benign_client_h2_shutdown(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("peer closed connection without sending tls close_notify")
        || lower.contains("unexpected-eof")
        || lower.contains("unexpected eof")
}

fn is_benign_client_h2_stream_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(h2_err) = cause.downcast_ref::<h2::Error>() {
            if matches!(
                h2_err.reason(),
                Some(Reason::CANCEL | Reason::NO_ERROR | Reason::STREAM_CLOSED)
            ) {
                return true;
            }
        }

        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::UnexpectedEof
            ) {
                return true;
            }
        }
    }

    is_benign_client_h2_shutdown(&err.to_string())
}

#[derive(Debug, Clone)]
struct Http2UpstreamAttempt {
    tls_plan: Option<TlsClientPlan>,
    upstream_mode: UpstreamMode,
    transport_note: Option<&'static str>,
}

/// Executes the full HTTP/2 request lifecycle for a single client stream.
async fn process_http2_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    body_limits: BodyLimitsConfig,
    fetcher: Arc<dyn OriginFetcher>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    peer: SocketAddr,
    sni: Option<String>,
    target_host: Option<String>,
) -> Result<()> {
    if is_h2_websocket_connect_request(&request) || is_h2_websocket_upgrade_request(&request) {
        return handle_h2_websocket_tunnel(request, respond, telemetry, peer, sni, target_host).await;
    }

    if is_proxy_runtime_asset_method_path(request.method(), request.uri().path()) {
        let mut flow = Flow::new(RequestParts {
            method: request.method().clone(),
            uri: request.uri().clone(),
            version: http::Version::HTTP_2,
            headers: request.headers().clone(),
            body: BodyBuffer::default(),
        });
        flow.metadata.tls_sni = sni.clone();
        flow.metadata.connect_target = target_host;
        flow.metadata.client_protocol = Some("h2".to_string());
        flow.metadata.request_protocol = Some("proxy-runtime-asset".to_string());
        flow.metadata.upstream_protocol = Some("local".to_string());
        flow.metadata.buffering_mode = Some("local-asset".to_string());
        flow.response = Some(build_proxy_runtime_asset_response(http::Version::HTTP_2, &flow.request.method)?);

        let response = flow.response.as_mut().context("runtime asset response missing")?;
        sanitize_response_headers_for_h2(response)?;
        let response = flow.response.as_ref().context("runtime asset response missing")?;
        send_http2_response(&mut respond, response).await?;
        emit_flow_telemetry(&telemetry, &flow, &sni, peer);
        return Ok(());
    }

    let request_parts = request_parts_from_h2(request, body_limits.max_request_body_bytes).await?;
    let mut flow = Flow::new(request_parts);
    flow.metadata.tls_sni = sni.clone();
    flow.metadata.connect_target = target_host;
    flow.metadata.client_protocol = Some("h2".to_string());

    stages.process_request(&mut flow).await?;

    let (host, port) = resolve_upstream_target(&flow);
    let mut respond = respond;
    let upstream_attempts = http2_upstream_attempts(&flow.metadata.fingerprint_config, flow.id)?;

    let mut last_err = None;
    let total_attempts = upstream_attempts.len();
    for (attempt_index, attempt) in upstream_attempts.into_iter().enumerate() {
        flow.metadata.tls_variant_id = None;
        if let Some(plan) = &attempt.tls_plan {
            flow.metadata.tls_variant_id = Some(plan.variant_id().to_string());
            tracing::debug!(%peer, variant = plan.variant_id(), "selected TLS hello variant");
        }

        if let Some(note) = attempt.transport_note {
            flow.metadata.transport_notes.push(note.to_string());
        }

        tracing::debug!(%peer, %host, port, attempt = attempt_index + 1, "forwarding HTTP/2 stream upstream");

        match fetcher
            .fetch_streaming(
                &flow,
                &OriginTarget::new(host.clone(), port),
                attempt.tls_plan,
                attempt.upstream_mode,
            )
            .await
        {
        Ok(mut origin) => {
            tracing::debug!(
                %peer,
                status = %origin.response.status(),
                upstream_protocol = %origin.upstream_protocol,
                "received upstream HTTP/2 response"
            );
            flow.metadata.upstream_protocol = Some(origin.upstream_protocol);
            flow.response = Some(streaming_response_head(&origin.response));

            let requires_buffering = flow
                .response
                .as_ref()
                .map(|response| response_requires_body_buffering(&flow.request, response))
                .unwrap_or(false);
            let bootstrap_asset = is_bootstrap_asset_request(&flow.request);
            flow.metadata.buffering_mode = Some(if requires_buffering {
                if bootstrap_asset {
                    "buffered-h2-bootstrap".to_string()
                } else {
                    "buffered-h2-document".to_string()
                }
            } else {
                "streaming-h2-raw".to_string()
            });

            if requires_buffering {
                let prepare_result: Result<()> = async {
                    stages.process_response_headers(&mut flow).await?;

                    let response = flow
                        .response
                        .as_mut()
                        .context("response missing after upstream response headers")?;
                    response.body = buffer_streaming_response_body(
                        &mut origin.response,
                        body_limits.max_response_body_bytes,
                    )
                    .await?;

                    stages.process_response_body(&mut flow).await?;
                    stages.finalize_response(&mut flow).await?;
                    Ok(())
                }
                .await;

                if let Err(err) = prepare_result {
                    let should_retry = attempt_index + 1 < total_attempts
                        && is_retryable_upstream_stream_error(&err);
                    if should_retry {
                        tracing::warn!(
                            %peer,
                            %host,
                            attempt = attempt_index + 1,
                            error = %format_args!("{err:#}"),
                            "buffered upstream HTTP/2 response handling failed before downstream commit, retrying with alternate candidate"
                        );
                        flow.response = None;
                        last_err = Some(err);
                        continue;
                    }

                    return Err(err);
                }
            } else {
                stages.process_response_headers(&mut flow).await?;
                stages.process_response_body(&mut flow).await?;
                stages.finalize_response(&mut flow).await?;
            }

            if requires_buffering {
                let response = flow
                    .response
                    .as_mut()
                    .context("response missing after outbound fetch")?;
                normalize_bootstrap_asset_response(&flow.request, response);
                enforce_content_length(response)?;
                sanitize_response_headers_for_h2(response)?;
                let response = flow
                    .response
                    .as_ref()
                    .context("response missing after response stages")?;
                if let Err(err) = send_http2_response(&mut respond, response).await {
                    if is_benign_client_h2_stream_error(&err) {
                        tracing::debug!(
                            %peer,
                            status = %response.status,
                            error = %format_args!("{err:#}"),
                            "client closed/reset HTTP/2 stream before downstream response completed"
                        );
                        return Ok(());
                    }

                    return Err(err);
                }
            } else {
                let response = flow
                    .response
                    .as_mut()
                    .context("response missing after response stages")?;
                normalize_bootstrap_asset_response(&flow.request, response);
                sanitize_response_headers_for_h2(response)?;
                if let Err(err) = send_streaming_http2_response(
                    &mut respond,
                    response,
                    &mut origin.response,
                    &flow.request.method,
                    body_limits.max_response_body_bytes,
                )
                .await
                {
                    if is_benign_client_h2_stream_error(&err) {
                        tracing::debug!(
                            %peer,
                            status = %response.status,
                            error = %format_args!("{err:#}"),
                            "client closed/reset HTTP/2 stream before streamed downstream response completed"
                        );
                        return Ok(());
                    }

                    return Err(err);
                }
            }

            emit_flow_telemetry(&telemetry, &flow, &sni, peer);
            return Ok(());
        }
        Err(err) => {
            let should_retry = attempt_index + 1 < total_attempts && is_retryable_upstream_connect_error(&err);
            if should_retry {
                tracing::warn!(
                    %peer,
                    %host,
                    attempt = attempt_index + 1,
                    error = %format_args!("{err:#}"),
                    "upstream connect failed for selected TLS hello variant, retrying with alternate candidate"
                );
                last_err = Some(err);
                continue;
            }

            last_err = Some(err);
            break;
        }
        }
    }

    let err = last_err.context("upstream HTTP/2 forwarding failed without an error")?;
    respond.send_reset(Reason::INTERNAL_ERROR);
    tracing::error!(%peer, %host, error = %format_args!("{err:#}"), "failed to forward HTTP/2 stream");

    Err(err)
}

fn http2_upstream_attempts(
    profile: &serde_json::Value,
    flow_id: uuid::Uuid,
) -> Result<Vec<Http2UpstreamAttempt>> {
    let mut attempts = plan_attempts_from_profile_with_alpn(profile, flow_id, Some("h2"), 3)?
        .into_iter()
        .map(|plan| Http2UpstreamAttempt {
            tls_plan: Some(plan),
            upstream_mode: UpstreamMode::PreferHttp2,
            transport_note: None,
        })
        .collect::<Vec<_>>();

    if let Some(plan) = http1_tls_plan(profile, flow_id)? {
        attempts.push(Http2UpstreamAttempt {
            tls_plan: Some(plan),
            upstream_mode: UpstreamMode::Http1Only,
            transport_note: Some("upstream-http1-only-variant"),
        });
    }

    attempts.push(Http2UpstreamAttempt {
        tls_plan: None,
        upstream_mode: UpstreamMode::PreferHttp2,
        transport_note: Some("upstream-transparent-h2"),
    });

    Ok(attempts)
}

fn http1_tls_plan(
    profile: &serde_json::Value,
    flow_id: uuid::Uuid,
) -> Result<Option<TlsClientPlan>> {
    if let Some(plan) = plan_attempts_from_profile_with_alpn(profile, flow_id, None, usize::MAX)?
        .into_iter()
        .find(|plan| !plan_supports_h2_upstream(plan))
    {
        return Ok(Some(plan));
    }

    Ok(plan_from_profile(profile, flow_id)?
        .map(|plan| plan.clone_with_alpn(vec!["http/1.1".to_string()])))
}

fn streaming_response_head(response: &wreq::Response) -> ResponseParts {
    ResponseParts {
        status: response.status(),
        version: response.version(),
        headers: response.headers().clone(),
        body: BodyBuffer::default(),
    }
}

fn response_requires_body_buffering(request: &RequestParts, response: &ResponseParts) -> bool {
    if is_bootstrap_asset_request(request) {
        return true;
    }

    response
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("text/html") || value.contains("application/xhtml+xml")
        })
        .unwrap_or(false)
}

fn is_bootstrap_asset_request(request: &RequestParts) -> bool {
    if request.method != http::Method::GET && request.method != http::Method::HEAD {
        return false;
    }

    if request
        .headers
        .get("sec-fetch-dest")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.eq_ignore_ascii_case("script")
                || value.eq_ignore_ascii_case("worker")
                || value.eq_ignore_ascii_case("sharedworker")
                || value.eq_ignore_ascii_case("serviceworker")
        })
        .unwrap_or(false)
    {
        return true;
    }

    let path = request.uri.path().to_ascii_lowercase();
    path.ends_with(".js") || path.ends_with(".mjs") || path.ends_with("/sw.js")
}

fn normalize_bootstrap_asset_response(
    request: &RequestParts,
    response: &mut ResponseParts,
) {
    if !is_bootstrap_asset_request(request) {
        return;
    }

    response.headers.remove(ETAG);
    response.headers.remove(LAST_MODIFIED);
    response.headers.remove(EXPIRES);
    response
        .headers
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store, no-cache, must-revalidate"));
    response
        .headers
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

async fn buffer_streaming_response_body(
    response: &mut wreq::Response,
    max_response_body_bytes: usize,
) -> Result<BodyBuffer> {
    if let Some(content_length) = response.content_length() {
        if content_length > max_response_body_bytes as u64 {
            anyhow::bail!(
                "upstream response body exceeds configured limit of {max_response_body_bytes} bytes"
            );
        }
    }

    let mut body = BodyBuffer::default();
    while let Some(frame) = poll_fn(|cx| Pin::new(&mut *response).poll_frame(cx)).await {
        let frame = frame.context("failed to buffer upstream response body")?;
        if let Ok(chunk) = frame.into_data() {
            body.push_bytes_limited(&chunk, max_response_body_bytes, "upstream response body")?;
        }
    }
    Ok(body)
}

fn response_head_has_no_body(request_method: &http::Method, response: &wreq::Response) -> bool {
    request_method == http::Method::HEAD
        || response.status().is_informational()
        || response.status() == http::StatusCode::NO_CONTENT
        || response.status() == http::StatusCode::NOT_MODIFIED
        || response.content_length() == Some(0)
}

async fn send_streaming_http2_response(
    respond: &mut SendResponse<Bytes>,
    response_head: &ResponseParts,
    upstream_response: &mut wreq::Response,
    request_method: &http::Method,
    max_response_body_bytes: usize,
) -> Result<()> {
    let end_stream = response_head_has_no_body(request_method, upstream_response);
    let head = build_http2_response_head(response_head)?;
    let mut send_stream = respond
        .send_response(head, end_stream)
        .context("failed to send HTTP/2 response head")?;

    if end_stream {
        return Ok(());
    }

    let mut streamed_bytes = 0usize;
    while let Some(frame) = poll_fn(|cx| Pin::new(&mut *upstream_response).poll_frame(cx)).await {
        let frame = frame.context("failed to read upstream streamed response body")?;
        match frame.into_data() {
            Ok(chunk) => {
                streamed_bytes = streamed_bytes.saturating_add(chunk.len());
                if streamed_bytes > max_response_body_bytes {
                    anyhow::bail!(
                        "upstream streamed response body exceeds configured limit of {max_response_body_bytes} bytes"
                    );
                }
                send_h2_data(&mut send_stream, &chunk, false).await?;
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    send_stream
                        .send_trailers(trailers)
                        .context("failed to send HTTP/2 response trailers")?;
                    return Ok(());
                }
            }
        }
    }

    send_h2_data(&mut send_stream, &[], true).await
}

/// Accepts a TLS session on the given TCP socket, returning the encrypted stream and SNI.
async fn accept_tls_session(
    socket: TcpStream,
    tls: Arc<TlsProvider>,
    fallback_sni: Option<String>,
) -> Result<(ClientTlsStream, Option<String>)> {
    let config = build_server_config(tls, fallback_sni);

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let tls_stream = acceptor.accept(socket).await?;

    let negotiated_sni = extract_sni(tls_stream.get_ref().1);

    Ok((tls_stream, negotiated_sni))
}

/// Extracts the SNI hostname from a completed TLS handshake.
fn extract_sni(conn: &ServerConnection) -> Option<String> {

    conn.server_name().map(|name| name.to_owned())
}

fn handshake_fallback_sni(target_host: Option<&str>) -> Option<String> {
    target_host.map(connect_target_host)
}

fn normalize_content_length(headers: &mut http::HeaderMap, len: usize) -> Result<()> {
    headers.remove(http::header::TRANSFER_ENCODING);
    let value = HeaderValue::from_str(&len.to_string()).context("invalid content-length value")?;
    headers.insert(http::header::CONTENT_LENGTH, value);
    Ok(())
}

fn enforce_content_length(response: &mut ResponseParts) -> Result<()> {
    normalize_content_length(&mut response.headers, response.body.len())
}

struct ParsedHttpRequest {
    request: RequestParts,
    buffered_tail: Vec<u8>,
}

async fn parse_http_request<S>(stream: &mut S, max_request_body_bytes: usize) -> Result<ParsedHttpRequest>
where
    S: AsyncRead + Unpin,
{
    let (head, mut buffered_tail) = read_http_head(stream, MAX_HTTP_HEAD_BYTES).await?;
    let (method, target, version, headers) = parse_http_request_head(&head)?;

    let host = headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let uri = if target.starts_with("http://") || target.starts_with("https://") {
        http::Uri::try_from(target.to_string())
            .with_context(|| format!("invalid absolute request target: {target}"))?
    } else if host.is_empty() {
        http::Uri::try_from(target.to_string())
            .with_context(|| format!("invalid origin-form request target: {target}"))?
    } else {
        http::Uri::try_from(format!("https://{}{}", host, target))
            .with_context(|| format!("invalid synthesized request target: {host}{target}"))?
    };

    let body_len = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    if body_len > max_request_body_bytes {
        anyhow::bail!(
            "request body exceeds configured limit of {max_request_body_bytes} bytes"
        );
    }

    while buffered_tail.len() < body_len {
        let remaining = body_len - buffered_tail.len();
        let mut chunk = vec![0u8; remaining.min(16 * 1024)];
        let read = stream
            .read(&mut chunk)
            .await
            .with_context(|| format!("expected {body_len} request body bytes, hit read error"))?;
        if read == 0 {
            anyhow::bail!("expected {body_len} request body bytes, hit EOF");
        }
        buffered_tail.extend_from_slice(&chunk[..read]);
    }

    let mut body = BodyBuffer::default();
    if body_len > 0 {
        body.push_bytes_limited(&buffered_tail[..body_len], max_request_body_bytes, "request body")?;
    }
    let remaining_tail = buffered_tail.split_off(body_len);

    Ok(ParsedHttpRequest {
        request: RequestParts {
            method,
            uri,
            version,
            headers,
            body,
        },
        buffered_tail: remaining_tail,
    })
}

async fn read_http_head<S>(stream: &mut S, max_head_bytes: usize) -> Result<(Vec<u8>, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();

    loop {
        if let Some(end) = find_http_head_end(&buffer) {
            let tail = buffer.split_off(end);
            return Ok((buffer, tail));
        }

        if buffer.len() >= max_head_bytes {
            anyhow::bail!("HTTP head exceeds configured limit of {max_head_bytes} bytes");
        }

        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.context("failed to read HTTP head")?;
        if read == 0 {
            if buffer.is_empty() {
                anyhow::bail!("client closed connection before sending HTTP head");
            }
            anyhow::bail!("unexpected EOF while reading HTTP head");
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn find_http_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn parse_http_request_head(head: &[u8]) -> Result<(http::Method, String, http::Version, http::HeaderMap)> {
    let head_str = std::str::from_utf8(head).context("request head is not valid UTF-8")?;
    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().context("request head missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method_str = parts.next().context("request line missing method")?;
    let target = parts.next().context("request line missing target")?.to_string();
    let version = parse_http_version(parts.next().unwrap_or("HTTP/1.1"));
    let method = http::Method::from_bytes(method_str.as_bytes())
        .with_context(|| format!("invalid request method: {method_str}"))?;
    let headers = parse_http_headers(lines)?;
    Ok((method, target, version, headers))
}

fn parse_http_response_head(head: &[u8]) -> Result<ResponseParts> {
    let head_str = std::str::from_utf8(head).context("response head is not valid UTF-8")?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().context("response head missing status line")?;
    let mut parts = status_line.split_whitespace();
    let version = parse_http_version(parts.next().unwrap_or("HTTP/1.1"));
    let status_str = parts.next().context("response status line missing status code")?;
    let status = http::StatusCode::from_u16(
        status_str
            .parse()
            .with_context(|| format!("invalid response status code: {status_str}"))?,
    )
    .context("invalid response status code")?;
    let headers = parse_http_headers(lines)?;

    Ok(ResponseParts {
        status,
        version,
        headers,
        body: BodyBuffer::default(),
    })
}

fn parse_http_headers<'a, I>(lines: I) -> Result<http::HeaderMap>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut headers = http::HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some(colon_pos) = line.find(':') else {
            anyhow::bail!("invalid HTTP header line: {line}");
        };
        let (name, value) = line.split_at(colon_pos);
        let header_name = HeaderName::from_bytes(name.trim().as_bytes())
            .with_context(|| format!("invalid HTTP header name: {}", name.trim()))?;
        let header_value = HeaderValue::from_str(value[1..].trim())
            .with_context(|| format!("invalid HTTP header value for {}", name.trim()))?;
        headers.append(header_name, header_value);
    }
    Ok(headers)
}

fn parse_http_version(raw: &str) -> http::Version {
    match raw {
        "HTTP/1.0" => http::Version::HTTP_10,
        "HTTP/1.1" => http::Version::HTTP_11,
        "HTTP/2.0" | "HTTP/2" => http::Version::HTTP_2,
        _ => http::Version::HTTP_11,
    }
}

fn is_h2_websocket_connect_request<B>(request: &http::Request<B>) -> bool {
    request.method() == http::Method::CONNECT
        && request
            .extensions()
            .get::<H2Protocol>()
            .map(|protocol| protocol.as_str().eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
}

fn is_h2_websocket_upgrade_request<B>(request: &http::Request<B>) -> bool {
    request.method() == http::Method::GET && headers_indicate_websocket(request.headers())
}

async fn handle_h2_websocket_tunnel(
    request: http::Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    telemetry: TelemetrySink,
    peer: SocketAddr,
    sni: Option<String>,
    target_host: Option<String>,
) -> Result<()> {
    let (parts, recv_stream) = request.into_parts();
    let request_method = parts.method.clone();
    let request_protocol = parts
        .extensions
        .get::<H2Protocol>()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "websocket".to_string());
    let host = sni
        .clone()
        .or_else(|| target_host.as_ref().map(|value| connect_target_host(value)))
        .or_else(|| parts.uri.host().map(|value| value.to_string()))
        .unwrap_or_else(|| "example.com".to_string());
    let port = parts
        .uri
        .port_u16()
        .or_else(|| target_host.as_ref().and_then(|value| connect_target_port(value)))
        .unwrap_or(443);

    let tcp_stream = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("failed to connect extended CONNECT upstream {host}:{port}"))?;
    let connector = build_upstream_tls_connector()?;
    let server_name = ServerName::try_from(host.clone())
        .with_context(|| format!("invalid upstream TLS server name: {host}"))?;
    let mut upstream_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .with_context(|| format!("failed to establish upstream TLS for extended CONNECT {host}:{port}"))?;

    send_upstream_h2_websocket_handshake(&mut upstream_stream, &parts, &host, port).await?;

    let (response_head, upstream_buffered_tail) = read_http_head(&mut upstream_stream, MAX_HTTP_HEAD_BYTES)
        .await
        .context("failed to read upstream websocket upgrade response for h2 CONNECT")?;
    let mut response = parse_http_response_head(&response_head)?;
    let upstream_status = response.status;
    sanitize_websocket_connect_response_for_h2(&mut response, upstream_status)?;

    let mut flow = Flow::new(RequestParts {
        method: request_method.clone(),
        uri: parts.uri.clone(),
        version: http::Version::HTTP_2,
        headers: parts.headers.clone(),
        body: BodyBuffer::default(),
    });
    flow.metadata.tls_sni = sni.clone();
    flow.metadata.connect_target = target_host;
    flow.metadata.client_protocol = Some("h2".to_string());
    flow.metadata.request_protocol = Some(request_protocol.clone());
    flow.metadata.upstream_protocol = Some("http/1.1".to_string());
    flow.metadata.buffering_mode = Some("raw-h2-websocket-tunnel".to_string());
    flow.metadata.websocket_tunnel = true;
    if request_method == http::Method::CONNECT {
        flow.metadata.transport_notes.push(format!("extended-connect:{request_protocol}"));
    } else {
        flow.metadata.transport_notes.push(format!("h2-upgrade-compat:{request_protocol}"));
    }
    flow.response = Some(ResponseParts {
        status: response.status,
        version: http::Version::HTTP_2,
        headers: response.headers.clone(),
        body: BodyBuffer::default(),
    });

    let head = build_http2_response_head(&response)?;
    let mut send_stream = respond
        .send_response(head, false)
        .context("failed to send extended CONNECT response head")?;

    if !upstream_buffered_tail.is_empty() {
        send_h2_data(&mut send_stream, &upstream_buffered_tail, false).await?;
    }

    if upstream_status != http::StatusCode::SWITCHING_PROTOCOLS {
        let (mut upstream_reader, _) = split(upstream_stream);
        stream_upstream_reader_to_h2(&mut upstream_reader, &mut send_stream).await?;
        emit_flow_telemetry(&telemetry, &flow, &sni, peer);
        return Ok(());
    }

    let (mut upstream_reader, mut upstream_writer) = split(upstream_stream);
    let client_to_upstream = pump_h2_recv_to_upstream(recv_stream, &mut upstream_writer);
    let upstream_to_client = stream_upstream_reader_to_h2(&mut upstream_reader, &mut send_stream);
    tokio::try_join!(client_to_upstream, upstream_to_client)?;

    emit_flow_telemetry(&telemetry, &flow, &sni, peer);
    Ok(())
}

fn is_websocket_upgrade_request(request: &RequestParts) -> bool {
    request.method == http::Method::GET && headers_indicate_websocket(&request.headers)
}

fn headers_indicate_websocket(headers: &http::HeaderMap) -> bool {
    if headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return true;
    }

    let upgrade_is_websocket = headers
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection_mentions_upgrade = headers
        .get("connection")
        .and_then(|value| value.to_str().ok())
        .map(|value| header_contains_token(value, "upgrade"))
        .unwrap_or(false);

    headers.get("sec-websocket-key").is_some() || (upgrade_is_websocket && connection_mentions_upgrade)
}

fn header_contains_token(value: &str, expected: &str) -> bool {
    value
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case(expected))
}

fn build_upstream_tls_connector() -> Result<TlsConnector> {
    let native_certs = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(native_certs.certs);

    if !native_certs.errors.is_empty() {
        tracing::warn!(count = native_certs.errors.len(), "some native root certificates could not be loaded for websocket upstream TLS");
    }
    if added == 0 {
        anyhow::bail!("no native root certificates were loaded for websocket upstream TLS");
    }
    if ignored > 0 {
        tracing::debug!(ignored, "ignored unparsable native root certificates while building websocket upstream TLS connector");
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsConnector::from(Arc::new(config)))
}

async fn send_upstream_h2_websocket_handshake<S>(
    stream: &mut S,
    parts: &http::request::Parts,
    host: &str,
    port: u16,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let request_line = format!("GET {} HTTP/1.1\r\n", path);
    stream
        .write_all(request_line.as_bytes())
        .await
        .context("failed to write upstream extended CONNECT request line")?;

    let mut saw_host = false;
    let mut saw_connection = false;
    let mut saw_upgrade = false;
    for (name, value) in parts.headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "proxy-connection" || lower == "proxy-authenticate" || lower == "proxy-authorization" {
            continue;
        }
        if lower == "host" {
            saw_host = true;
        }
        if lower == "connection" {
            saw_connection = true;
        }
        if lower == "upgrade" {
            saw_upgrade = true;
        }
        stream.write_all(name.as_str().as_bytes()).await?;
        stream.write_all(b": ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }

    if !saw_host {
        let authority = if port == 443 { host.to_string() } else { format!("{}:{}", host, port) };
        stream.write_all(b"host: ").await?;
        stream.write_all(authority.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }
    if !saw_connection {
        stream.write_all(b"connection: Upgrade\r\n").await?;
    }
    if !saw_upgrade {
        stream.write_all(b"upgrade: websocket\r\n").await?;
    }

    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    Ok(())
}

async fn send_upstream_http1_request<S>(
    stream: &mut S,
    request: &RequestParts,
    host: &str,
    port: u16,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let path = request
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let request_line = format!("{} {} HTTP/1.1\r\n", request.method, path);
    stream
        .write_all(request_line.as_bytes())
        .await
        .context("failed to write upstream request line")?;

    let mut saw_host = false;
    for (name, value) in request.headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "proxy-connection" || lower == "proxy-authenticate" || lower == "proxy-authorization" {
            continue;
        }
        if name == http::header::HOST {
            saw_host = true;
        }
        stream.write_all(name.as_str().as_bytes()).await?;
        stream.write_all(b": ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }

    if !saw_host {
        let authority = if port == 443 { host.to_string() } else { format!("{}:{}", host, port) };
        stream.write_all(b"host: ").await?;
        stream.write_all(authority.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }

    stream.write_all(b"\r\n").await?;
    if !request.body.is_empty() {
        stream.write_all(request.body.as_bytes()).await?;
    }
    stream.flush().await?;
    Ok(())
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
];

/// Normalizes response headers so they comply with RFC 7540 requirements.
fn sanitize_response_headers_for_h2(response: &mut ResponseParts) -> Result<()> {
    let mut sanitized = http::HeaderMap::new();
    for (name, value) in response.headers.iter() {
        let lowered = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP_HEADERS.iter().any(|hop| hop == &lowered) {
            continue;
        }

        let header_name = HeaderName::from_bytes(lowered.as_bytes())
            .context("invalid header name during HTTP/2 normalization")?;
        sanitized.append(header_name, value.clone());
    }

    response.headers = sanitized;
    Ok(())
}

fn sanitize_websocket_connect_response_for_h2(
    response: &mut ResponseParts,
    upstream_status: http::StatusCode,
) -> Result<()> {
    sanitize_response_headers_for_h2(response)?;
    if upstream_status == http::StatusCode::SWITCHING_PROTOCOLS {
        response.status = http::StatusCode::OK;
    }
    response.version = http::Version::HTTP_2;
    Ok(())
}

fn build_http2_response_head(response: &ResponseParts) -> Result<http::Response<()>> {
    let mut builder = http::Response::builder()
        .status(response.status)
        .version(http::Version::HTTP_2);

    for (name, value) in response.headers.iter() {
        builder = builder.header(name, value);
    }

    builder
        .body(())
        .map_err(|err| anyhow!("failed to build HTTP/2 response head: {err}"))
}

async fn send_h2_data(stream: &mut SendStream<Bytes>, data: &[u8], end_stream: bool) -> Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        if stream.capacity() == 0 {
            let requested = (data.len() - offset).min(H2_SEND_CHUNK_SIZE);
            stream.reserve_capacity(requested);
            match poll_fn(|cx| stream.poll_capacity(cx)).await {
                Some(Ok(_)) => {}
                Some(Err(err)) => return Err(err).context("failed while waiting for HTTP/2 send capacity"),
                None => anyhow::bail!("HTTP/2 send stream closed while waiting for capacity"),
            }
        }

        let writable = stream.capacity().min(data.len() - offset).min(H2_SEND_CHUNK_SIZE);
        let chunk = Bytes::copy_from_slice(&data[offset..offset + writable]);
        offset += writable;
        stream
            .send_data(chunk, end_stream && offset == data.len())
            .context("failed to write HTTP/2 tunnel chunk")?;
    }

    if data.is_empty() && end_stream {
        stream
            .send_data(Bytes::new(), true)
            .context("failed to close HTTP/2 tunnel stream")?;
    }

    Ok(())
}

async fn pump_h2_recv_to_upstream(
    mut recv_stream: h2::RecvStream,
    upstream_writer: &mut WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
) -> Result<()> {
    while let Some(frame) = recv_stream.data().await {
        let chunk = frame?;
        upstream_writer
            .write_all(&chunk)
            .await
            .context("failed to forward extended CONNECT data upstream")?;
        recv_stream
            .flow_control()
            .release_capacity(chunk.len())
            .context("failed to release extended CONNECT receive capacity")?;
    }

    upstream_writer
        .shutdown()
        .await
        .context("failed to close upstream extended CONNECT writer")?;
    Ok(())
}

async fn stream_upstream_reader_to_h2<R>(
    upstream_reader: &mut R,
    send_stream: &mut SendStream<Bytes>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; H2_SEND_CHUNK_SIZE];
    loop {
        let read = upstream_reader
            .read(&mut buffer)
            .await
            .context("failed to read upstream tunnel bytes")?;
        if read == 0 {
            send_h2_data(send_stream, &[], true).await?;
            break;
        }
        send_h2_data(send_stream, &buffer[..read], false).await?;
    }
    Ok(())
}

async fn send_http2_response(respond: &mut SendResponse<Bytes>, response: &ResponseParts) -> Result<()> {
    let head = build_http2_response_head(response)?;
    let end_stream = response.body.is_empty();
    let mut send_stream = respond
        .send_response(head, end_stream)
        .context("failed to send HTTP/2 response head")?;
    if !end_stream {
        send_h2_data(&mut send_stream, response.body.as_bytes(), true).await?;
    }
    Ok(())
}

/// Serializes the staged HTTP/1.x response back to the client.
async fn send_response_to_client<S>(
    client: &mut S,
    response: &ResponseParts,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let reason = response.status.canonical_reason().unwrap_or("");
    let status_line = format!(
        "{} {} {}\r\n",
        match response.version {
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_11 => "HTTP/1.1",
            http::Version::HTTP_2 => "HTTP/2.0",
            _ => "HTTP/1.1",
        },
        response.status.as_u16(),
        reason
    );
    client.write_all(status_line.as_bytes()).await?;

    for (name, value) in response.headers.iter() {
        client.write_all(name.as_str().as_bytes()).await?;
        client.write_all(b": ").await?;
        client.write_all(value.as_bytes()).await?;
        client.write_all(b"\r\n").await?;
    }

    client.write_all(b"\r\n").await?;

    if !response.body.is_empty() {
        client.write_all(response.body.as_bytes()).await?;
    }

    client.flush().await?;
    Ok(())
}

/// Converts an `h2::RecvStream` into our HTTP/1-style `RequestParts` container.
async fn request_parts_from_h2(
    request: http::Request<h2::RecvStream>,
    max_request_body_bytes: usize,
) -> Result<RequestParts> {
    let (parts, mut body_stream) = request.into_parts();
    let mut body = BodyBuffer::default();

    while let Some(frame) = body_stream.data().await {
        let chunk = frame?;
        body.push_bytes_limited(&chunk, max_request_body_bytes, "request body")?;
        body_stream
            .flow_control()
            .release_capacity(chunk.len())
            .context("failed to release client HTTP/2 flow-control capacity")?;
    }

    let mut headers = parts.headers;
    if let Some(trailers) = body_stream.trailers().await? {
        for (name, value) in trailers.iter() {
            headers.append(name.clone(), value.clone());
        }
    }

    Ok(RequestParts {
        method: parts.method,
        uri: parts.uri,
        version: http::Version::HTTP_2,
        headers,
        body,
    })
}

fn resolve_upstream_target(flow: &Flow) -> (String, u16) {
    let host = flow
        .metadata
        .tls_sni
        .clone()
        .or_else(|| {
            flow.metadata
                .connect_target
                .as_ref()
                .map(|t| connect_target_host(t))
        })
        .or_else(|| flow.request.uri.host().map(|h| h.to_string()))
        .unwrap_or_else(|| "example.com".to_string());

    let port = flow
        .request
        .uri
        .port_u16()
        .or_else(|| {
            flow.metadata
                .connect_target
                .as_ref()
                .and_then(|t| connect_target_port(t))
        })
        .unwrap_or_else(|| match flow.request.uri.scheme_str() {
            Some("http") => 80,
            _ => 443,
        });

    (host, port)
}

fn connect_target_host(target: &str) -> String {
    target.split(':').next().unwrap_or(target).to_string()
}

fn connect_target_port(target: &str) -> Option<u16> {
    target.split(':').nth(1)?.parse().ok()
}

fn error_chain_contains_message(err: &anyhow::Error, needles: &[&str]) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string().to_ascii_lowercase();
        needles.iter().any(|needle| message.contains(needle))
    })
}

fn is_retryable_upstream_connect_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::BrokenPipe
            ) {
                return true;
            }
        }
    }

    error_chain_contains_message(
        err,
        &[
            "forcibly closed by the remote host",
            "unexpected eof",
            "handshake_failure_on_client_hello",
            "sslv3_alert_handshake_failure",
            "alert_unexpected_message",
            "sslv3_alert_unexpected_message",
        ],
    )
}

fn is_retryable_upstream_stream_error(err: &anyhow::Error) -> bool {
    if is_retryable_upstream_connect_error(err) {
        return true;
    }

    error_chain_contains_message(
        err,
        &[
            "failed to buffer upstream response body",
            "failed to read upstream streamed response body",
            "protocol error",
            "stream error",
            "unexpected eof",
        ],
    )
}

fn is_proxy_runtime_asset_request(request: &RequestParts) -> bool {
    is_proxy_runtime_asset_method_path(&request.method, request.uri.path())
}

fn is_proxy_runtime_asset_method_path(method: &http::Method, path: &str) -> bool {
    (*method == http::Method::GET || *method == http::Method::HEAD) && path == RUNTIME_ASSET_PATH
}

fn build_proxy_runtime_asset_response(
    version: http::Version,
    method: &http::Method,
) -> Result<ResponseParts> {
    let bundle = ScriptBundle::load();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, must-revalidate"),
    );

    let mut body = BodyBuffer::default();
    if *method != http::Method::HEAD {
        body.replace(bundle.runtime.as_bytes());
    }

    let mut response = ResponseParts {
        status: http::StatusCode::OK,
        version,
        headers,
        body,
    };
    enforce_content_length(&mut response)?;
    Ok(response)
}

fn emit_flow_telemetry(
    telemetry: &TelemetrySink,
    flow: &Flow,
    sni: &Option<String>,
    peer: SocketAddr,
) {
    telemetry.emit(
        "flow_placeholder",
        flow.id,
        serde_json::json!({
            "peer": peer.to_string(),
            "sni": sni,
            "profile": flow.metadata.profile_name,
            "alt_svc": flow.metadata.alt_svc_mutations,
            "client_protocol": flow.metadata.client_protocol,
            "request_protocol": flow.metadata.request_protocol,
            "upstream_protocol": flow.metadata.upstream_protocol,
            "buffering_mode": flow.metadata.buffering_mode,
            "websocket_tunnel": flow.metadata.websocket_tunnel,
            "transport_notes": flow.metadata.transport_notes,
            "tls_variant_id": flow.metadata.tls_variant_id,
            "tls_version": flow.metadata.tls_version,
            "tls_cipher_suite": flow.metadata.tls_cipher_suite,
        }),
    );
}

/// Resolves TLS certificates dynamically during the handshake based on client-requested SNI.
#[derive(Debug)]
struct OnDemandCertResolver {

    provider: Arc<TlsProvider>,

    fallback: String,
}

impl OnDemandCertResolver {

    fn new(provider: Arc<TlsProvider>, fallback_sni: Option<String>) -> Self {
        Self {
            provider,
            fallback: fallback_sni.unwrap_or_else(|| FALLBACK_SNI.to_string()),
        }
    }
}

impl ResolvesServerCert for OnDemandCertResolver {
    /// Called synchronously during the TLS handshake to resolve a certificate for the client's SNI.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {

        let requested = client_hello
            .server_name()
            .map(|s| s.to_owned())
            .unwrap_or_else(|| self.fallback.clone());

        match self.provider.certified_key(&requested) {
            Ok(cert) => Some(cert),
            Err(err) => {

                tracing::error!(hostname = %requested, "failed to mint certificate: {err:?}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        handshake_fallback_sni,
        http1_tls_plan,
        http2_upstream_attempts,
        is_retryable_upstream_connect_error,
        is_retryable_upstream_stream_error,
        is_benign_client_h2_shutdown, is_benign_client_h2_stream_error,
        is_bootstrap_asset_request, normalize_bootstrap_asset_response,
        is_h2_websocket_upgrade_request, parse_http_request_head,
        parse_http_response_head, resolve_upstream_target, response_requires_body_buffering,
    };
    use crate::proxy::fetcher::UpstreamMode;
    use crate::proxy::{BodyBuffer, Flow, RequestParts, ResponseParts};
    use http::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE, ETAG, PRAGMA};
    use http::{Method, Uri, Version};
    use uuid::Uuid;

    #[test]
    fn benign_h2_stream_error_accepts_reset_like_io_kinds() {
        let err = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "stream reset by peer",
        ));

        assert!(is_benign_client_h2_stream_error(&err));
    }

    #[test]
    fn benign_h2_stream_error_rejects_unrelated_io_kinds() {
        let err = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "write timed out",
        ));

        assert!(!is_benign_client_h2_stream_error(&err));
    }

    #[test]
    fn benign_h2_shutdown_matches_known_close_notify_pattern() {
        assert!(is_benign_client_h2_shutdown(
            "peer closed connection without sending TLS close_notify"
        ));
    }

    #[test]
    fn response_requires_buffering_for_html_documents() {
        let request = RequestParts::default();
        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );

        assert!(response_requires_body_buffering(&request, &response));
    }

    #[test]
    fn resolve_upstream_target_defaults_plain_http_to_port_80() {
        let mut flow = Flow::new(RequestParts {
            method: Method::GET,
            uri: Uri::from_static("http://detectportal.firefox.com/canonical.html"),
            version: Version::HTTP_11,
            headers: http::HeaderMap::new(),
            body: BodyBuffer::default(),
        });
        flow.metadata.tls_sni = None;
        flow.metadata.connect_target = None;

        let (host, port) = resolve_upstream_target(&flow);

        assert_eq!(host, "detectportal.firefox.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn response_skips_buffering_for_non_document_content() {
        let request = RequestParts::default();
        let mut response = ResponseParts::default();
        response.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript"),
        );

        assert!(!response_requires_body_buffering(&request, &response));
    }

    #[test]
    fn bootstrap_asset_requests_require_buffering() {
        let mut request = RequestParts {
            method: Method::GET,
            uri: Uri::from_static("https://app.tuta.com/common-min-vt_wlNjZ.js"),
            version: Version::HTTP_11,
            headers: http::HeaderMap::new(),
            body: crate::proxy::BodyBuffer::default(),
        };
        request
            .headers
            .insert("sec-fetch-dest", HeaderValue::from_static("script"));

        assert!(is_bootstrap_asset_request(&request));
        assert!(response_requires_body_buffering(&request, &ResponseParts::default()));
    }

    #[test]
    fn retryable_upstream_stream_errors_accept_protocol_failures() {
        let err = anyhow::anyhow!("failed to read upstream streamed response body: protocol error: stream closed");

        assert!(is_retryable_upstream_stream_error(&err));
    }

    #[test]
    fn bootstrap_asset_response_is_marked_no_store() {
        let mut request = RequestParts {
            method: Method::GET,
            uri: Uri::from_static("https://app.tuta.com/sw.js"),
            version: Version::HTTP_11,
            headers: http::HeaderMap::new(),
            body: crate::proxy::BodyBuffer::default(),
        };
        request
            .headers
            .insert("sec-fetch-dest", HeaderValue::from_static("serviceworker"));

        let mut response = ResponseParts::default();
        response.headers.insert(ETAG, HeaderValue::from_static("\"etag\""));

        normalize_bootstrap_asset_response(&request, &mut response);

        assert_eq!(
            response.headers.get(CACHE_CONTROL).and_then(|value| value.to_str().ok()),
            Some("no-store, no-cache, must-revalidate")
        );
        assert_eq!(
            response.headers.get(PRAGMA).and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert!(response.headers.get(ETAG).is_none());
    }

    #[test]
    fn http2_attempts_include_profiled_http11_fallback_before_transparent_h2() {
        let profile: serde_json::Value = serde_json::from_str(include_str!("../../profiles/chrome-windows.json"))
            .expect("profile should parse");

        let attempts = http2_upstream_attempts(&profile, Uuid::nil()).expect("attempts should build");

        assert!(attempts.len() >= 4);
        assert!(attempts.iter().take(attempts.len() - 2).all(|attempt| matches!(attempt.upstream_mode, UpstreamMode::PreferHttp2) && attempt.tls_plan.is_some()));
        let http1_fallback = &attempts[attempts.len() - 2];
        assert!(matches!(http1_fallback.upstream_mode, UpstreamMode::Http1Only));
        assert_eq!(http1_fallback.transport_note, Some("upstream-http1-only-variant"));
        assert_eq!(http1_fallback.tls_plan.as_ref().map(|plan| plan.variant_id()), Some("ch_h1_fallback"));
        let fallback = attempts.last().expect("fallback attempt should exist");
        assert!(fallback.tls_plan.is_none());
        assert_eq!(fallback.transport_note, Some("upstream-transparent-h2"));
        assert!(matches!(fallback.upstream_mode, UpstreamMode::PreferHttp2));
    }

    #[test]
    fn retryable_upstream_connect_errors_exclude_dns_failures() {

        #[test]
        fn parse_http_request_head_rejects_header_without_colon() {
            let err = parse_http_request_head(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Broken\r\n\r\n",
            )
            .expect_err("malformed request header should fail");

            assert!(err.to_string().contains("invalid HTTP header line: X-Broken"));
        }

        #[test]
        fn parse_http_response_head_rejects_header_without_colon() {
            let err = parse_http_response_head(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection upgrade\r\n\r\n",
            )
            .expect_err("malformed response header should fail");

            assert!(err.to_string().contains("invalid HTTP header line: Connection upgrade"));
        }
        let dns_err = anyhow::anyhow!("client error (Connect): dns error: No such host is known. (os error 11001)");
        let handshake_err = anyhow::anyhow!("client error (Connect): [SSLV3_ALERT_HANDSHAKE_FAILURE] [HANDSHAKE_FAILURE_ON_CLIENT_HELLO]");
        let unexpected_message_err = anyhow::anyhow!("client error (Connect): [SSLV3_ALERT_UNEXPECTED_MESSAGE]: [SSLV3_ALERT_UNEXPECTED_MESSAGE]");

        assert!(!is_retryable_upstream_connect_error(&dns_err));
        assert!(is_retryable_upstream_connect_error(&handshake_err));
        assert!(is_retryable_upstream_connect_error(&unexpected_message_err));
    }

    #[test]
    fn retryable_upstream_connect_errors_match_nested_unexpected_eof_causes() {
        let err = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "client error (Connect): unexpected EOF",
        ))
        .context("client error (Connect)")
        .context("wreq fetch failed: method=GET uri=https://lh3.google.com mode=prefer-http2");

        assert!(is_retryable_upstream_connect_error(&err));
    }

    #[test]
    fn handshake_fallback_sni_uses_connect_target_host() {
        assert_eq!(
            handshake_fallback_sni(Some("api.github.com:443")).as_deref(),
            Some("api.github.com")
        );
        assert!(handshake_fallback_sni(None).is_none());
    }

    #[test]
    fn http1_tls_plan_prefers_an_explicit_http11_only_variant() {
        let profile: serde_json::Value = serde_json::from_str(include_str!("../../profiles/chrome-windows.json"))
            .expect("profile should parse");

        let plan = http1_tls_plan(&profile, Uuid::nil())
            .expect("plan selection should succeed")
            .expect("a plan should be available");

        assert_eq!(plan.variant_id(), "ch_h1_fallback");
        assert!(!plan.alpn_protocols().iter().any(|value| value == "h2"));
    }

    #[test]
    fn h2_websocket_upgrade_detector_accepts_firefox_style_get_upgrade() {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://app.tuta.com/event")
            .header("upgrade", "websocket")
            .header("sec-websocket-key", "Rk0NBrpRwcptpSehYOYMBA==")
            .body(())
            .expect("request should build");

        assert!(is_h2_websocket_upgrade_request(&request));
    }
}
