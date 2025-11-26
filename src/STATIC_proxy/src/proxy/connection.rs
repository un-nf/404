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

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use h2::{client, server::SendResponse, Reason, SendStream};
use http::{header::{HeaderName, HeaderValue, HOST}, StatusCode};
use rustls::{server::ClientHello, server::ResolvesServerCert, ServerConfig};
use rustls::{sign::CertifiedKey, ServerConnection};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::{timeout, Duration};
use tokio::net::TcpStream;
use tokio_rustls::{client as rustls_client, server as rustls_server, TlsAcceptor};

use crate::{
    proxy::{
        flow::BodyBuffer, flow::Flow, flow::RequestParts, flow::ResponseParts,
        stages::StagePipeline,
    },
    telemetry::TelemetrySink,
    tls::{
        cert::TlsProvider,
        profiles::{plan_from_profile, TlsClientPlan},
    },
};

use super::client::UpstreamClient;

/// Tokio-friendly alias for the client-facing TLS stream (rustls over TCP).
///
/// **Type Explanation:**
/// - TcpStream: The underlying socket from tokio's async runtime
/// - TlsStream: tokio-rustls wrapper that handles encryption/decryption transparently
///
/// After the handshake completes, reads/writes on this type are automatically encrypted/decrypted
/// by rustls, so application code (HTTP parsing, etc.) sees plaintext.
type ClientTlsStream = rustls_server::TlsStream<TcpStream>;
type UpstreamTlsStream = rustls_client::TlsStream<TcpStream>;

/// Fallback hostname used when the client omits SNI (Server Name Indication).
///
/// **When This Happens:**
/// - Ancient clients (pre-2010) that don't support SNI extension
/// - Command-line tools like curl when SNI is explicitly disabled
/// - Localhost testing with IP addresses instead of hostnames
///
/// **Why "static.local"?**
/// - Deterministic: prevents panics in TlsProvider when SNI is None
/// - Recognizable: makes it obvious in logs when SNI is missing
/// - Cached: ensures we don't generate a new cert for every SNI-less connection
///
/// Browsers practically always send SNI, so this is a rare edge case in production.
const FALLBACK_SNI: &str = "static.local";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Detects whether the connection is HTTP or HTTPS by peeking at the first byte.
///
/// **TLS Detection:**
/// TLS handshake always starts with a ClientHello record:
/// - Byte 0: 0x16 (Handshake record type)
/// - Byte 1-2: TLS version (0x03 0x01 for TLS 1.0, 0x03 0x03 for TLS 1.2, etc.)
///
/// **HTTP Detection:**
/// HTTP requests start with ASCII method names:
/// - "GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "CONN", "TRAC"
///
/// **Why This Matters:**
/// If a client sends plaintext HTTP to the proxy, we need to return a helpful error
/// instead of trying to parse it as TLS (which causes "InvalidContentType" errors).
///
/// **Implementation:**
/// Use tokio's `peek()` to read the first byte without consuming it from the stream.
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

/// Handles a single client connection from TCP accept through TLS termination, protocol routing,
/// stage execution, and upstream forwarding.
///
/// **Connection Lifecycle:**
/// 1. Peek the first byte to decide whether we need to honor an HTTP CONNECT tunnel.
/// 2. Complete the TLS handshake using on-demand certificates (bounded by `HANDSHAKE_TIMEOUT`).
/// 3. Route the decrypted stream into HTTP/1.1 or HTTP/2 handlers based on ALPN.
/// 4. Parse the request, run the stage pipeline, and dial the upstream with a matching TLS plan.
/// 5. Stream the upstream response back to the client while emitting telemetry for the flow.
///
/// Errors are bubbled up with peer/SNI context so the caller can log and continue serving other clients.
pub async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    tls: Arc<TlsProvider>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    http3_enabled: bool,
) -> Result<()> {
    // Detect protocol before attempting TLS handshake
    let protocol = detect_protocol(&socket).await?;

    let target_host = match protocol {
        Protocol::Http => {
            // Browser is sending HTTP CONNECT for tunnel establishment
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
        Protocol::Unknown => {
            tracing::warn!(%peer, "rejecting connection with unknown protocol");
            return Err(anyhow::anyhow!("unknown protocol"));
        }
        Protocol::Tls => {
            // Direct TLS connection (rare, but supported)
            tracing::debug!(%peer, "direct TLS connection detected");
            None
        }
    };

    tracing::debug!(%peer, "starting TLS handshake");

    // Complete the asynchronous TLS handshake using on-demand certificates.
    // This gives us a decrypted stream and the client's requested hostname (SNI).
    let handshake = timeout(HANDSHAKE_TIMEOUT, accept_tls_session(socket, tls)).await;
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
            handle_http2_session(client_tls, peer, stages, telemetry, sni, target_host).await
        }
        _ => {
            tracing::debug!(%peer, "falling back to HTTP/1.1");
            handle_http1_session(client_tls, peer, stages, telemetry, sni, target_host).await
        }
    }
}

/// Handles HTTP CONNECT tunnel establishment for browser proxy connections.
///
/// **What is CONNECT?**
/// Standard HTTP proxy protocol for tunneling. Browser sends:
/// ```text
/// CONNECT example.com:443 HTTP/1.1
/// Host: example.com:443
/// Proxy-Connection: keep-alive
///
/// ```
///
/// **This Function:**
/// 1. Reads the CONNECT request line (`CONNECT host:port HTTP/1.1`)
/// 2. Validates it's a CONNECT request
/// 3. Consumes remaining headers until blank line
/// 4. Sends `200 Connection Established` response
/// 5. Returns the target host for logging/telemetry
///
/// **After Return:**
/// Socket is positioned for the client to initiate TLS handshake over the tunnel.
/// This is the standard browser → HTTPS proxy → TLS sequence.
///
/// **Error Cases:**
/// - Malformed CONNECT request (not starting with "CONNECT")
/// - I/O errors reading from socket
async fn handle_connect_tunnel(socket: &mut TcpStream) -> Result<String> {
    let mut reader = BufReader::new(socket);
    let mut request_line = String::new();

    // Read the CONNECT request line
    reader
        .read_line(&mut request_line)
        .await
        .context("failed to read CONNECT request line")?;

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();

    if parts.len() < 2 || parts[0] != "CONNECT" {
        anyhow::bail!("invalid CONNECT request: {}", request_line);
    }

    let target = parts[1].to_string();

    // Consume remaining headers until blank line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Send 200 Connection Established response
    // After this, client will initiate TLS handshake
    let socket = reader.into_inner();
    socket
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("failed to send 200 Connection Established")?;

    tracing::debug!(target = %target, "sent 200 Connection Established");
    Ok(target)
}

/// Builds a rustls ServerConfig that dynamically issues certificates per-SNI.
///
/// **rustls 0.23 Builder Pattern:**
/// 1. Start with ServerConfig::builder()
/// 2. Call with_no_client_auth() (we don't validate client certificates for MITM)
/// 3. Call with_cert_resolver() and pass our OnDemandCertResolver
///
/// **Why No Client Auth?**
/// Client certificate validation (mTLS) would break most HTTPS connections because
/// browsers don't present certificates unless the site explicitly requires them.
/// We only validate the client's trust of our CA certificate.
///
/// **Certificate Resolver:**
/// OnDemandCertResolver implements rustls::server::ResolvesServerCert, which is called
/// synchronously during the handshake. It uses TlsProvider to mint per-SNI certificates
/// from the shared CA, with caching to avoid regenerating certs for repeat hostnames.
///
/// **ALPN (Application-Layer Protocol Negotiation):**
/// We advertise `h2` and `http/1.1` so the client-facing handshake can negotiate HTTP/2 while
/// falling back to HTTP/1.1 for browsers that do not support it.
///

fn build_server_config(tls: Arc<TlsProvider>) -> ServerConfig {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OnDemandCertResolver::new(tls)));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// Orchestrates the HTTP/1.1 data path once TLS is terminated.
///
/// **Flow:**
/// 1. Parse the client's request off the decrypted stream (entire body buffered in `Flow::request`).
/// 2. Run request stages so header/profile mutations land before we dial upstream.
/// 3. Dial the origin with an HTTP/1.1-only TLS plan, mirror the request, and buffer the full response.
/// 4. Execute response stages, enforce `Content-Length`, emit telemetry, and serialize the response back to the client.
///
/// **Invariants:**
/// - `Flow.request` and `Flow.response` always contain owned buffers; no streaming occurs yet.
/// - `Content-Length` must be enforced after response stages mutate the body (callers rely on that before `send_response_to_client`).
/// - Metadata (`tls_sni`, `connect_target`, `client_protocol`, `upstream_protocol`) is populated for downstream telemetry/hooks.
///
/// **Limitations:**
/// Buffering both directions makes large bodies memory-heavy; when we introduce streaming stages this function must change accordingly.
async fn handle_http1_session(
    mut client_stream: ClientTlsStream,
    peer: SocketAddr,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    sni: Option<String>,
    target_host: Option<String>,
) -> Result<()> {
    let request = parse_http_request(&mut client_stream).await?;
    tracing::debug!(%peer, method = %request.method, uri = %request.uri, "parsed HTTP/1.1 request");

    let mut flow = Flow::new(request);
    flow.metadata.tls_sni = sni.clone();
    flow.metadata.connect_target = target_host;
    flow.metadata.client_protocol = Some("http/1.1".to_string());

    stages.process_request(&mut flow).await?;

    let mut tls_plan = plan_from_profile(&flow.metadata.fingerprint_config, flow.id)?;
    if let Some(plan) = tls_plan.take() {
        tls_plan = Some(plan.clone_with_alpn(vec![b"http/1.1".to_vec()]));
    }
    if let Some(plan) = &tls_plan {
        tracing::debug!(%peer, variant = plan.variant_id(), "selected TLS hello variant");
    }

    let (host, port) = resolve_upstream_target(&flow);
    tracing::debug!(%peer, %host, port, "connecting to upstream (HTTP/1.1)");
    let mut upstream = UpstreamClient::connect(
        &host,
        port,
        tls_plan.as_ref(),
        Some(vec![b"http/1.1".to_vec()]),
    )
    .await?;

    let upstream_proto = negotiated_protocol_label(upstream.get_ref().1.alpn_protocol());
    flow.metadata.upstream_protocol =
        Some(upstream_proto.unwrap_or_else(|| "http/1.1".to_string()));

    send_request_to_upstream(&mut upstream, &flow.request).await?;
    tracing::debug!(%peer, "request forwarded to upstream");

    let response_parts = parse_http_response(&mut upstream, &flow.request.method).await?;
    tracing::debug!(%peer, status = %response_parts.status, "received upstream response");
    flow.response = Some(response_parts);

    stages.process_response_headers(&mut flow).await?;
    stages.process_response_body(&mut flow).await?;
    stages.finalize_response(&mut flow).await?;

    if let Some(response) = flow.response.as_mut() {
        enforce_content_length(response)?;
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

/// Terminates the client-facing HTTP/2 connection and spins up per-stream tasks.
///
/// **Concurrency Model:**
/// `h2::server::handshake` yields a `Connection` that we hold on the main task; every
/// inbound stream is accepted, cloned pipeline/telemetry handles are captured, and the
/// work moves into its own tokio task via `process_http2_stream`.
///
/// **Backpressure:**
/// The parent loop keeps polling `connection.accept()` so new streams can arrive
/// even while existing ones are awaiting upstream responses.
async fn handle_http2_session(
    client_stream: ClientTlsStream,
    peer: SocketAddr,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    sni: Option<String>,
    target_host: Option<String>,
) -> Result<()> {
    let mut connection = h2::server::handshake(client_stream)
        .await
        .context("failed to negotiate HTTP/2 with client")?;

    while let Some(result) = connection.accept().await {
        let (request, respond) = result?;
        let stages_clone = stages.clone();
        let telemetry_clone = telemetry.clone();
        let sni_clone = sni.clone();
        let target_clone = target_host.clone();

        tokio::spawn(async move {
            if let Err(err) = process_http2_stream(
                request,
                respond,
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

/// Executes the full HTTP/2 request lifecycle for a single client stream.
///
/// **Steps:**
/// 1. Convert the `h2::RecvStream` into `RequestParts`, buffering pseudo-headers + body.
/// 2. Populate Flow metadata (SNI, CONNECT info, client protocol) and run request stages.
/// 3. Derive a TLS client plan, resolve the upstream target, and forward via `forward_h2_request`.
/// 4. Emit telemetry regardless of success so operators can correlate per-stream failures.
///
/// Errors bubble up so the caller can reset the stream/log context.
async fn process_http2_stream(
    request: http::Request<h2::RecvStream>,
    respond: SendResponse<Bytes>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    peer: SocketAddr,
    sni: Option<String>,
    target_host: Option<String>,
) -> Result<()> {
    let request_parts = request_parts_from_h2(request).await?;
    let mut flow = Flow::new(request_parts);
    flow.metadata.tls_sni = sni.clone();
    flow.metadata.connect_target = target_host;
    flow.metadata.client_protocol = Some("h2".to_string());

    stages.process_request(&mut flow).await?;

    let tls_plan = plan_from_profile(&flow.metadata.fingerprint_config, flow.id)?;
    if let Some(plan) = &tls_plan {
        tracing::debug!(%peer, variant = plan.variant_id(), "selected TLS hello variant");
    }

    let (host, port) = resolve_upstream_target(&flow);
    tracing::debug!(%peer, %host, port, "forwarding HTTP/2 stream upstream");

    match forward_h2_request(&mut flow, &host, port, tls_plan, &stages, respond).await {
        Ok(_) => {
            emit_flow_telemetry(&telemetry, &flow, &sni, peer);
            Ok(())
        }
        Err(err) => {
            tracing::error!(%peer, %host, "failed to forward HTTP/2 stream: {err:?}");
            Err(err)
        }
    }
}

/// Accepts a TLS session on the given TCP socket, returning the encrypted stream and SNI.
///
/// **Async Handshake Flow:**
/// 1. Build a ServerConfig with on-demand cert resolver
/// 2. Wrap it in a TlsAcceptor (tokio-rustls entry point)
/// 3. Call acceptor.accept(socket), which:
///    - Reads ClientHello from the socket
///    - Calls OnDemandCertResolver::resolve to get a certificate
///    - Sends ServerHello with the certificate
///    - Completes the TLS 1.2/1.3 handshake (key exchange, Finished messages)
/// 4. Return the wrapped TlsStream (automatically encrypts/decrypts all I/O)
///
/// **SNI Extraction:**
/// After the handshake, we call extract_sni() on the negotiated ServerConnection.
/// rustls 0.23 stores the SNI hostname as an Option<&str>, which we clone into
/// an owned String for storage in Flow::metadata.
///
/// **Error Cases:**
/// - Client sends malformed TLS handshake → Err (socket closes)
/// - Client doesn't trust our CA → Err (certificate validation failure)
/// - Certificate resolver panics/fails → Err (logged in OnDemandCertResolver::resolve)
///
/// **Thread Safety:**
/// This is an async function running in a tokio task. Multiple connections can
/// handshake concurrently, with TlsProvider's DashMap ensuring lock-free cert caching.
async fn accept_tls_session(
    socket: TcpStream,
    tls: Arc<TlsProvider>,
) -> Result<(ClientTlsStream, Option<String>)> {
    // Build the rustls configuration with on-demand certificate resolver
    let config = build_server_config(tls);

    // Wrap in TlsAcceptor (tokio-rustls async API)
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Perform the async TLS handshake (yields to tokio runtime during I/O)
    let tls_stream = acceptor.accept(socket).await?;

    // Extract the negotiated SNI hostname from the rustls connection state
    // .get_ref() returns (TcpStream, ServerConnection); we want .1 for the TLS state
    let negotiated_sni = extract_sni(tls_stream.get_ref().1);

    Ok((tls_stream, negotiated_sni))
}

/// Extracts the SNI hostname from a completed TLS handshake.
///
/// **rustls 0.23 API:**
/// ServerConnection::server_name() returns Option<&str> (not an enum as in older versions).
/// We map it to an owned String so downstream stages can store it in Flow::metadata
/// without lifetime complications.
///
/// **SNI Primer:**
/// Server Name Indication (SNI) is a TLS extension where the client announces the
/// hostname it's trying to reach in plaintext during the ClientHello. This allows:
/// - Virtual hosting: one IP can serve multiple domains with different certs
/// - MITM proxies: we can issue a certificate matching the requested hostname
///
/// **Why Option?**
/// - Old clients (pre-2010) don't send SNI
/// - Command-line tools sometimes omit SNI
/// - IP-based requests (https://192.0.2.1) have no hostname to indicate
///
/// When None, we fall back to FALLBACK_SNI ("static.local") in the cert resolver.
fn extract_sni(conn: &ServerConnection) -> Option<String> {
    // rustls 0.23: .server_name() returns Option<&str>
    conn.server_name().map(|name| name.to_owned())
}

/// Parses a single HTTP/1.1 request from the client-facing TLS stream.
///
/// **What it captures:** method, URI, version, headers, and (if present) an entire `Content-Length` body.
///
/// **Invariants:**
/// - Runs on a fresh client socket that still contains the full HTTP request.
/// - Stops reading exactly after the declared body bytes so subsequent code can reuse the same stream.
/// - Any missing/invalid `Content-Length` yields an empty body (pipeline stages must guard on that).
///
/// **Limitations:**
/// - Request-side chunked encoding is unsupported; browsers rarely emit chunked uploads but we must add it later.
/// - Entire bodies are buffered, which is acceptable for header mutation but not for arbitrarily large uploads.
/// - Hyper/httparse would provide stricter validation; this routine intentionally stays minimal for now.
async fn parse_http_request(stream: &mut ClientTlsStream) -> Result<RequestParts> {
    let mut reader = tokio::io::BufReader::new(stream);
    let mut line = String::new();

    // Read request line: "GET /path HTTP/1.1"
    reader.read_line(&mut line).await?;
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!("malformed HTTP request line"));
    }

    let method = parts[0].parse::<http::Method>()?;
    let uri = parts[1].parse::<http::Uri>()?;
    let version = match parts[2] {
        "HTTP/1.0" => http::Version::HTTP_10,
        "HTTP/1.1" => http::Version::HTTP_11,
        "HTTP/2.0" => http::Version::HTTP_2,
        _ => http::Version::HTTP_11,
    };

    // Read headers
    let mut headers = http::HeaderMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break; // End of headers
        }

        if let Some(colon_pos) = line.find(':') {
            let name = &line[..colon_pos].trim();
            let value = &line[colon_pos + 1..].trim();
            if let (Ok(header_name), Ok(header_value)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                http::header::HeaderValue::from_str(value),
            ) {
                headers.insert(header_name, header_value);
            }
        }
    }

    // Read body if Content-Length is present
    let mut body = BodyBuffer::default();
    if let Some(content_length) = headers.get(http::header::CONTENT_LENGTH) {
        if let Ok(len_str) = content_length.to_str() {
            if let Ok(len) = len_str.parse::<usize>() {
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                body.push_bytes(&buf);
            }
        }
    }

    Ok(RequestParts {
        method,
        uri,
        version,
        headers,
        body,
    })
}

/// Parses the entire HTTP/1.x response from the upstream origin.
///
/// **Responsibilities:**
/// - Validate the status line and version, rejecting truncated responses early.
/// - Canonicalize hop-by-hop body semantics: ignore 1xx/204/205/304 payloads, honor HEAD semantics, and detect chunked bodies.
/// - Buffer the full response body (fixed length or decoded chunked) into `BodyBuffer`, normalizing `Content-Length` when needed.
///
/// **Limitations:**
/// - Full-body buffering keeps stage logic simple but increases latency/memory for very large payloads.
/// - Trailer headers are currently discarded; when stage logic cares about them we will need to surface them.
async fn parse_http_response(
    stream: &mut UpstreamTlsStream,
    request_method: &http::Method,
) -> Result<ResponseParts> {
    let mut reader = BufReader::new(stream);

    let mut status_line = String::new();
    let read = reader
        .read_line(&mut status_line)
        .await
        .context("failed to read response status line")?;
    if read == 0 {
        anyhow::bail!("upstream closed connection before sending status line");
    }

    let status_line = trim_crlf(&status_line);
    let mut parts = status_line.splitn(3, ' ');
    let version_str = parts.next().context("response line missing HTTP version")?;
    let status_str = parts.next().context("response line missing status code")?;

    let version = match version_str {
        "HTTP/1.0" => http::Version::HTTP_10,
        "HTTP/1.1" => http::Version::HTTP_11,
        "HTTP/2.0" => http::Version::HTTP_2,
        _ => http::Version::HTTP_11,
    };

    let status_code: u16 = status_str
        .parse()
        .with_context(|| format!("invalid status code: {status_str}"))?;
    let status = StatusCode::from_u16(status_code)
        .with_context(|| format!("unsupported status code: {status_code}"))?;

    let mut headers = http::HeaderMap::new();
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .context("failed to read response header line")?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading response headers");
        }
        let trimmed = trim_crlf(&line);
        if trimmed.is_empty() {
            break;
        }
        if let Some(colon_pos) = trimmed.find(':') {
            let (name, value) = trimmed.split_at(colon_pos);
            let header_name = name.trim();
            let header_value = value[1..].trim();
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(header_name.as_bytes()),
                http::header::HeaderValue::from_str(header_value),
            ) {
                headers.append(name, value);
            }
        }
    }

    let mut response = ResponseParts {
        status,
        version,
        headers,
        body: BodyBuffer::default(),
    };

    match response_body_encoding(&response.headers, &response.status, request_method) {
        BodyEncoding::None => {}
        BodyEncoding::ContentLength(len) => {
            read_fixed_body(&mut reader, len, &mut response.body).await?;
        }
        BodyEncoding::Chunked => {
            read_chunked_body(&mut reader, &mut response.body).await?;
            normalize_content_length(&mut response.headers, response.body.len())?;
        }
    }

    Ok(response)
}

/// Reads an exact number of bytes from the buffered reader into the response body.
///
/// Zero-length bodies short-circuit so HEAD/204 responses skip unnecessary syscalls.
async fn read_fixed_body<R>(
    reader: &mut BufReader<R>,
    len: usize,
    body: &mut BodyBuffer,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    if len == 0 {
        return Ok(());
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .with_context(|| format!("expected {len} body bytes, hit EOF"))?;
    body.push_bytes(&buf);
    Ok(())
}

/// Streams a chunked transfer-encoding body into memory while validating every boundary.
///
/// We parse hexadecimal sizes, strip any chunk extensions, enforce CRLF terminators, and
/// consume the optional trailer section before returning.
async fn read_chunked_body<R>(reader: &mut BufReader<R>, body: &mut BodyBuffer) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut size_line = String::new();
        let read = reader
            .read_line(&mut size_line)
            .await
            .context("failed to read chunk size line")?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading chunk size");
        }

        let size_str = trim_crlf(&size_line);
        let size_token = size_str.split(';').next().unwrap_or(size_str);
        let size = usize::from_str_radix(size_token, 16)
            .with_context(|| format!("invalid chunk size: {size_token}"))?;

        if size == 0 {
            consume_trailer_section(reader).await?;
            break;
        }

        let mut chunk = vec![0u8; size];
        reader
            .read_exact(&mut chunk)
            .await
            .with_context(|| format!("expected {size} chunk bytes, hit EOF"))?;
        body.push_bytes(&chunk);

        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .await
            .context("failed to read chunk terminator")?;
        if crlf != [b'\r', b'\n'] {
            anyhow::bail!("chunk missing CRLF terminator");
        }
    }
    Ok(())
}

async fn consume_trailer_section<R>(reader: &mut BufReader<R>) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await?;
        if read == 0 || line.trim().is_empty() {
            break;
        }
    }
    Ok(())
}

fn trim_crlf(input: &str) -> &str {
    input.trim_end_matches(|c| c == '\r' || c == '\n')
}

enum BodyEncoding {
    None,
    ContentLength(usize),
    Chunked,
}

fn response_body_encoding(
    headers: &http::HeaderMap,
    status: &StatusCode,
    method: &http::Method,
) -> BodyEncoding {
    if method == http::Method::HEAD {
        return BodyEncoding::None;
    }

    if status.is_informational() {
        return BodyEncoding::None;
    }

    match status.as_u16() {
        204 | 205 | 304 => {
            return BodyEncoding::None;
        }
        _ => {}
    }

    if has_chunked_encoding(headers) {
        return BodyEncoding::Chunked;
    }
    if let Some(value) = headers.get(http::header::CONTENT_LENGTH) {
        if let Ok(len_str) = value.to_str() {
            if let Ok(len) = len_str.parse::<usize>() {
                return BodyEncoding::ContentLength(len);
            }
        }
    }
    BodyEncoding::None
}

fn has_chunked_encoding(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            raw.to_ascii_lowercase()
                .split(',')
                .any(|enc| enc.trim() == "chunked")
        })
        .unwrap_or(false)
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

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
];

/// Normalizes response headers so they comply with RFC 7540 requirements.
///
/// Hop-by-hop headers (Connection, TE, etc.) are stripped, and remaining names are
/// lowercased because HTTP/2 mandates lowercase field names on the wire.
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

/// Sends an HTTP/2 response to the client, ensuring HEADERS are emitted before DATA.
///
/// We keep the returned `SendStream` alive for the entire body transfer to avoid the
/// h2 crate flushing DATA frames before the header block is acknowledged. Large bodies
/// are chunked into 16KB frames to maintain flow-control friendliness.
fn send_http2_response(
    respond: &mut SendResponse<Bytes>,
    response: &ResponseParts,
) -> Result<()> {
    let response_head = build_http2_response_head(response)?;
    let has_body = !response.body.is_empty();

    let mut stream = respond
        .send_response(response_head, !has_body)
        .context("failed to send HTTP/2 response headers to client")?;

    if has_body {
        stream_http2_body(&mut stream, response.body.as_bytes())
            .context("failed to stream HTTP/2 response body to client")?;
    }

    Ok(())
}

fn stream_http2_body(stream: &mut SendStream<Bytes>, body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Ok(());
    }

    const CHUNK_SIZE: usize = 16 * 1024;
    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + CHUNK_SIZE).min(body.len());
        let chunk = Bytes::copy_from_slice(&body[offset..end]);
        let end_stream = end == body.len();
        stream
            .send_data(chunk, end_stream)
            .context("failed to write HTTP/2 response chunk")?;
        offset = end;
    }

    Ok(())
}

/// Sends an HTTP request to the upstream server.
///
/// **Purpose:**
/// After parsing the client's HTTP request and establishing an upstream TLS connection,
/// we need to forward that request to the origin server. This function serializes the
/// RequestParts back into HTTP/1.1 wire format.
///
/// **Format:**
/// ```text
/// GET /search?q=test HTTP/1.1\r\n
/// Host: www.google.com\r\n
/// User-Agent: Mozilla/5.0...\r\n
/// \r\n
/// [optional body bytes]
/// ```
///
/// **Why Reconstruct?**
/// We already parsed the request from the client, so why rebuild it? Because:
/// 1. Pipeline stages may have mutated headers (User-Agent spoofing, CSP injection)
/// 2. We need to send to a different connection (upstream TLS, not client TLS)
/// 3. HTTP/1.1 requires proper line endings (\r\n) and header formatting
///
/// **Body Handling:**
/// If the request has a body (POST/PUT), we send it after headers. Body is already
/// buffered in RequestParts.body from parse_http_request.
async fn send_request_to_upstream<W>(upstream: &mut W, req: &RequestParts) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // Build request line: "GET /path HTTP/1.1\r\n"
    let request_line = format!(
        "{} {} HTTP/1.1\r\n",
        req.method,
        req.uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/"),
    );
    upstream.write_all(request_line.as_bytes()).await?;

    // Write headers
    for (name, value) in &req.headers {
        upstream.write_all(name.as_str().as_bytes()).await?;
        upstream.write_all(b": ").await?;
        upstream.write_all(value.as_bytes()).await?;
        upstream.write_all(b"\r\n").await?;
    }

    // Blank line to end headers
    upstream.write_all(b"\r\n").await?;

    // Write body if present
    if req.body.len() > 0 {
        upstream.write_all(req.body.as_bytes()).await?;
    }

    upstream.flush().await?;

    Ok(())
}

/// Serializes the staged HTTP/1.x response back to the client.
///
/// **Assumptions:**
/// - `ResponseParts` already carries a valid status/version and enforced `Content-Length` (no chunked bodies emitted downstream).
/// - Headers are sanitized for hop-by-hop correctness before this function runs.
///
/// **Behavior:**
/// Emits the status line, every header as raw bytes, a blank line, and finally the full body buffer.
/// The entire response is flushed before returning so the caller can drop the TLS stream immediately after.
async fn send_response_to_client(
    client: &mut ClientTlsStream,
    response: &ResponseParts,
) -> Result<()> {
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
///
/// We copy all pseudo/regular headers, buffer the entire DATA stream (releasing
/// flow-control credits for every chunk), then merge trailers back into the
/// header map so downstream stages can observe them.
async fn request_parts_from_h2(request: http::Request<h2::RecvStream>) -> Result<RequestParts> {
    let (parts, mut body_stream) = request.into_parts();
    let mut body = BodyBuffer::default();

    while let Some(frame) = body_stream.data().await {
        let chunk = frame?;
        body.push_bytes(&chunk);
        if let Err(err) = body_stream.flow_control().release_capacity(chunk.len()) {
            tracing::warn!(?err, "failed to release client HTTP/2 flow-control capacity");
            break;
        }
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

/// Forwards a single HTTP/2 flow to the origin, falling back to HTTP/1.1 when needed.
///
/// On failure we reset the client stream with INTERNAL_ERROR so browsers tear down the
/// request promptly instead of hanging.
async fn forward_h2_request(
    flow: &mut Flow,
    host: &str,
    port: u16,
    tls_plan: Option<TlsClientPlan>,
    stages: &StagePipeline,
    respond: SendResponse<Bytes>,
) -> Result<()> {
    let mut respond = respond;
    match forward_h2_request_inner(flow, host, port, tls_plan, stages, &mut respond).await {
        Ok(_) => Ok(()),
        Err(err) => {
            respond.send_reset(Reason::INTERNAL_ERROR);
            tracing::debug!("sent HTTP/2 reset after forwarding failure: {err:?}");
            Err(err)
        }
    }
}

/// Chooses the appropriate upstream strategy based on ALPN negotiation.
///
/// If the origin does not speak HTTP/2 for this hostname, we drop into the HTTP/1 bridge
/// while keeping Flow metadata updated so telemetry reflects the downgrade.
async fn forward_h2_request_inner(
    flow: &mut Flow,
    host: &str,
    port: u16,
    tls_plan: Option<TlsClientPlan>,
    stages: &StagePipeline,
    respond: &mut SendResponse<Bytes>,
) -> Result<()> {
    let tls_plan = tls_plan.map(|plan| plan.clone_with_alpn(vec![b"h2".to_vec()]));
    let upstream = UpstreamClient::connect(host, port, tls_plan.as_ref(), None).await?;
    let negotiated = negotiated_protocol_label(upstream.get_ref().1.alpn_protocol())
        .unwrap_or_else(|| "http/1.1".to_string());

    if negotiated != "h2" {
        tracing::warn!(
            %host,
            port,
            negotiated = %negotiated,
            "upstream lacks HTTP/2 support, falling back to HTTP/1.1",
        );
        flow.metadata.upstream_protocol = Some(negotiated);
        return forward_h2_via_http1(flow, upstream, host, port, stages, respond).await;
    }

    flow.metadata.upstream_protocol = Some(negotiated);
    forward_h2_over_h2(flow, &host, upstream, stages, respond).await
}

/// Bridges HTTP/2 end-to-end (client h2 → upstream h2) while keeping flow-control healthy.
///
/// **Key behaviors:**
/// - Reuses the client's headers/pseudo-headers so fingerprinting stages stay honest.
/// - Buffers request bodies (until streaming support lands) but streams DATA upstream
///   immediately afterward.
/// - Wraps the upstream response future in a 10s timeout and releases flow-control credits
///   for every body chunk we read.
async fn forward_h2_over_h2(
    flow: &mut Flow,
    host: &str,
    upstream: UpstreamTlsStream,
    stages: &StagePipeline,
    respond: &mut SendResponse<Bytes>,
) -> Result<()> {
    let (mut client_handle, connection) = client::handshake(upstream)
        .await
        .context("failed to start HTTP/2 handshake upstream")?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!("upstream h2 connection closed: {err:?}");
        }
    });

    let mut builder = http::Request::builder()
        .method(flow.request.method.clone())
        .uri(flow.request.uri.clone())
        .version(http::Version::HTTP_2);

    for (name, value) in flow.request.headers.iter() {
        builder = builder.header(name, value);
    }

    let request = builder.body(()).context("failed to build HTTP/2 request")?;
    let end_of_stream = flow.request.body.len() == 0;
    let path = flow
        .request
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let authority = flow
        .request
        .uri
        .authority()
        .map(|auth| auth.as_str().to_string())
        .or_else(|| {
            flow.request
                .headers
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| host.to_string());
    tracing::debug!(
        %host,
        method = %flow.request.method,
        path,
        authority,
        body_bytes = flow.request.body.len(),
        "sending HTTP/2 request upstream"
    );
    let (response_future, mut send_stream) = client_handle
        .send_request(request, end_of_stream)
        .context("failed to send HTTP/2 request upstream")?;

    if !end_of_stream {
        send_stream
            .send_data(Bytes::copy_from_slice(flow.request.body.as_bytes()), true)
            .context("failed to stream HTTP/2 request body upstream")?;
    }

    let response = match timeout(Duration::from_secs(10), response_future).await {
        Ok(Ok(resp)) => {
            tracing::debug!(%host, status = %resp.status(), "received upstream HTTP/2 response headers");
            resp
        }
        Ok(Err(err)) => {
            tracing::error!(%host, "upstream HTTP/2 request failed before headers: {err:?}");
            return Err(err.into());
        }
        Err(_) => {
            tracing::warn!(%host, "upstream HTTP/2 response timed out after 10s");
            let _ = respond.send_reset(Reason::CANCEL);
            anyhow::bail!("HTTP/2 upstream response timed out for {host}");
        }
    };
    let (parts, mut body_stream) = response.into_parts();
    let mut body = BodyBuffer::default();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk?;
        let len = chunk.len();
        body.push_bytes(chunk.as_ref());
        // Return flow-control credit so large responses keep streaming.
        if let Err(err) = body_stream.flow_control().release_capacity(len) {
            tracing::warn!(%host, ?err, "failed to release HTTP/2 flow-control capacity");
            break;
        }
    }

    flow.response = Some(ResponseParts {
        status: parts.status,
        version: http::Version::HTTP_2,
        headers: parts.headers,
        body,
    });

    stages.process_response_headers(flow).await?;
    stages.process_response_body(flow).await?;
    stages.finalize_response(flow).await?;

    let response = flow
        .response
        .as_mut()
        .context("response missing after HTTP/2 upstream fetch")?;
    enforce_content_length(response)?;
    sanitize_response_headers_for_h2(response)?;
    send_http2_response(respond, response)?;

    Ok(())
}

/// Downgrades a client HTTP/2 stream to an HTTP/1.1 upstream when the origin lacks h2.
///
/// Ensures a Host header is present, reuses the normal HTTP/1 serializer, runs response
/// stages, then re-encodes the mutated payload back into HTTP/2 frames for the client.
async fn forward_h2_via_http1(
    flow: &mut Flow,
    mut upstream: UpstreamTlsStream,
    host: &str,
    port: u16,
    stages: &StagePipeline,
    respond: &mut SendResponse<Bytes>,
) -> Result<()> {
    ensure_host_header(&mut flow.request, host, port);
    send_request_to_upstream(&mut upstream, &flow.request)
        .await
        .context("failed to send HTTP/1.1 request upstream")?;

    let response = parse_http_response(&mut upstream, &flow.request.method)
        .await
        .context("failed to parse HTTP/1.1 response during fallback")?;
    flow.response = Some(response);

    stages.process_response_headers(flow).await?;
    stages.process_response_body(flow).await?;
    stages.finalize_response(flow).await?;

    {
        let response_mut = flow
            .response
            .as_mut()
            .context("response missing during HTTP/1.1 fallback")?;
        enforce_content_length(response_mut)?;
        sanitize_response_headers_for_h2(response_mut)?;
    }

    let response_ref = flow
        .response
        .as_ref()
        .context("response missing during HTTP/1.1 fallback")?;
    send_http2_response(respond, response_ref)?;

    Ok(())
}

fn ensure_host_header(request: &mut RequestParts, host: &str, port: u16) {
    if request.headers.contains_key(HOST) {
        return;
    }

    let host_value = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };

    if let Ok(value) = HeaderValue::from_str(&host_value) {
        request.headers.insert(HOST, value);
    } else {
        tracing::warn!(host = %host_value, "failed to synthesize Host header for HTTP/1 fallback");
    }
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
        .unwrap_or(443);

    (host, port)
}

fn connect_target_host(target: &str) -> String {
    target.split(':').next().unwrap_or(target).to_string()
}

fn connect_target_port(target: &str) -> Option<u16> {
    target.split(':').nth(1)?.parse().ok()
}

fn negotiated_protocol_label(value: Option<&[u8]>) -> Option<String> {
    value.map(|proto| String::from_utf8_lossy(proto).into_owned())
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
            "upstream_protocol": flow.metadata.upstream_protocol,
        }),
    );
}

/// Resolves TLS certificates dynamically during the handshake based on client-requested SNI.
///
/// **Purpose:**
/// rustls calls this during the handshake (synchronously, not async) to get the certificate
/// chain + private key for the requested hostname. We use TlsProvider to mint certificates
/// on-the-fly, caching them in memory for repeat connections.
///
/// **Why Synchronous?**
/// The TLS handshake runs in a state machine that can't yield to async. Fortunately,
/// TlsProvider's cache makes this fast (DashMap lookup + Arc clone on cache hit).
/// On cache miss, we generate and sign a new certificate, which is ~100µs on modern CPUs.
///
/// **Trait Bounds:**
/// - Debug: Required by rustls::server::ResolvesServerCert (for logging/debugging)
/// - Send + Sync: Required because ServerConfig is shared across tokio tasks
///
/// **Fallback Behavior:**
/// If the client omits SNI, we use FALLBACK_SNI ("static.local"). This prevents panics
/// and ensures deterministic behavior in tests and with legacy clients.
#[derive(Debug)]
struct OnDemandCertResolver {
    /// Shared TlsProvider for certificate generation and caching.
    /// Arc allows multiple tasks to share the same provider without cloning the CA.
    provider: Arc<TlsProvider>,

    /// Fallback hostname when SNI is absent (prevents panics, keeps cache predictable).
    fallback: String,
}

impl OnDemandCertResolver {
    /// Creates a new resolver wrapping the given TlsProvider.
    fn new(provider: Arc<TlsProvider>) -> Self {
        Self {
            provider,
            fallback: FALLBACK_SNI.to_string(),
        }
    }
}

impl ResolvesServerCert for OnDemandCertResolver {
    /// Called synchronously during the TLS handshake to resolve a certificate for the client's SNI.
    ///
    /// **Handshake Flow:**
    /// 1. Client sends ClientHello with SNI extension (e.g., "api.github.com")
    /// 2. rustls parses the ClientHello and calls this method
    /// 3. We check TlsProvider's cache for a matching certificate
    /// 4. On cache hit: return the cached Arc<CertifiedKey>
    /// 5. On cache miss: generate a new leaf cert, sign it with CA, cache it, return it
    /// 6. rustls includes the certificate in the ServerHello
    /// 7. Client validates the cert chain (leaf → CA → trusted root)
    ///
    /// **Error Handling:**
    /// If certificate generation fails (extremely rare), we log the error and return None.
    /// rustls will abort the handshake with a "certificate_required" alert.
    ///
    /// **Performance:**
    /// - Cache hit: ~1µs (DashMap lookup + Arc clone)
    /// - Cache miss: ~100µs (rcgen key generation + signing + DashMap insert)
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Extract the SNI hostname from the ClientHello, or use fallback if absent
        let requested = client_hello
            .server_name()
            .map(|s| s.to_owned())
            .unwrap_or_else(|| self.fallback.clone());

        // Ask TlsProvider for a certificate (cache-or-generate pattern)
        match self.provider.certified_key(&requested) {
            Ok(cert) => Some(cert),
            Err(err) => {
                // Log the error for debugging, but don't panic (graceful degradation)
                tracing::error!(hostname = %requested, "failed to mint certificate: {err:?}");
                None
            }
        }
    }
}
