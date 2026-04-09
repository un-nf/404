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
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use h2::{server::SendResponse, Reason, SendStream};
use http::header::{HeaderName, HeaderValue};
use rustls::{server::ClientHello, server::ResolvesServerCert, ServerConfig};
use rustls::{sign::CertifiedKey, ServerConnection};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{timeout, Duration};
use tokio::net::TcpStream;
use tokio_rustls::{server as rustls_server, TlsAcceptor};

use crate::{
    proxy::{
        fetcher::{OriginFetcher, OriginTarget, UpstreamMode},
        flow::BodyBuffer, flow::Flow, flow::RequestParts, flow::ResponseParts,
        stages::StagePipeline,
    },
    telemetry::TelemetrySink,
    tls::{
        cert::TlsProvider,
        profiles::plan_from_profile
    },
};

/// Tokio-friendly alias for the client-facing TLS stream (rustls over TCP).
type ClientTlsStream = rustls_server::TlsStream<TcpStream>;

const FALLBACK_SNI: &str = "static.local";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Handles a single client connection from TCP accept through TLS termination, protocol routing,
pub async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    tls: Arc<TlsProvider>,
    fetcher: Arc<dyn OriginFetcher>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    _http3_enabled: bool,
) -> Result<()> {

    let protocol = detect_protocol(&socket).await?;

    let target_host = match protocol {
        Protocol::Http => {

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

            tracing::debug!(%peer, "direct TLS connection detected");
            None
        }
    };

    tracing::debug!(%peer, "starting TLS handshake");

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
            handle_http2_session(
                client_tls,
                peer,
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
fn build_server_config(tls: Arc<TlsProvider>) -> ServerConfig {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OnDemandCertResolver::new(tls)));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// Orchestrates the HTTP/1.1 data path once TLS is terminated.
async fn handle_http1_session(

    mut client_stream: ClientTlsStream,
    peer: SocketAddr,
    fetcher: Arc<dyn OriginFetcher>,
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
        tls_plan = Some(plan.clone_with_alpn(vec!["http/1.1".to_string()]));
    }
    if let Some(plan) = &tls_plan {
        flow.metadata.tls_variant_id = Some(plan.variant_id().to_string());
        tracing::debug!(%peer, variant = plan.variant_id(), "selected TLS hello variant");
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
async fn handle_http2_session(
    client_stream: ClientTlsStream,
    peer: SocketAddr,
    fetcher: Arc<dyn OriginFetcher>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
    sni: Option<String>,
    target_host: Option<String>,
) -> Result<()> {
    let mut connection = match h2::server::handshake(client_stream).await {
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

        tokio::spawn(async move {
            if let Err(err) = process_http2_stream(
                request,
                respond,
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

/// Executes the full HTTP/2 request lifecycle for a single client stream.
async fn process_http2_stream(
    request: http::Request<h2::RecvStream>,
    respond: SendResponse<Bytes>,
    fetcher: Arc<dyn OriginFetcher>,
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
        flow.metadata.tls_variant_id = Some(plan.variant_id().to_string());
        tracing::debug!(%peer, variant = plan.variant_id(), "selected TLS hello variant");
    }

    let (host, port) = resolve_upstream_target(&flow);
    tracing::debug!(%peer, %host, port, "forwarding HTTP/2 stream upstream");

    let mut respond = respond;
    match fetcher
        .fetch(
            &flow,
            &OriginTarget::new(host.clone(), port),
            tls_plan,
            UpstreamMode::PreferHttp2,
        )
        .await
    {
        Ok(origin) => {
            tracing::debug!(
                %peer,
                status = %origin.response.status,
                upstream_protocol = %origin.upstream_protocol,
                "received upstream HTTP/2 response"
            );
            flow.metadata.upstream_protocol = Some(origin.upstream_protocol);
            flow.response = Some(origin.response);

            stages.process_response_headers(&mut flow).await?;
            stages.process_response_body(&mut flow).await?;
            stages.finalize_response(&mut flow).await?;

            {
                let response = flow
                    .response
                    .as_mut()
                    .context("response missing after outbound fetch")?;
                enforce_content_length(response)?;
                sanitize_response_headers_for_h2(response)?;
            }

            let response = flow
                .response
                .as_ref()
                .context("response missing after response stages")?;
            if let Err(err) = send_http2_response(&mut respond, response) {
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
            emit_flow_telemetry(&telemetry, &flow, &sni, peer);
            Ok(())
        }
        Err(err) => {
            respond.send_reset(Reason::INTERNAL_ERROR);
            tracing::error!(%peer, %host, error = %format_args!("{err:#}"), "failed to forward HTTP/2 stream");

            Err(err)
        }
    }
}

/// Accepts a TLS session on the given TCP socket, returning the encrypted stream and SNI.
async fn accept_tls_session(
    socket: TcpStream,
    tls: Arc<TlsProvider>,
) -> Result<(ClientTlsStream, Option<String>)> {
    let config = build_server_config(tls);

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let tls_stream = acceptor.accept(socket).await?;

    let negotiated_sni = extract_sni(tls_stream.get_ref().1);

    Ok((tls_stream, negotiated_sni))
}

/// Extracts the SNI hostname from a completed TLS handshake.
fn extract_sni(conn: &ServerConnection) -> Option<String> {

    conn.server_name().map(|name| name.to_owned())
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

async fn parse_http_request(stream: &mut ClientTlsStream) -> Result<RequestParts> {
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    let read = reader
        .read_line(&mut request_line)
        .await
        .context("failed to read request line")?;
    if read == 0 {
        anyhow::bail!("client closed connection before sending request line");
    }

    let request_line = request_line.trim_end_matches(|c| c == '\r' || c == '\n');
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("request line missing method")?;
    let target = parts.next().context("request line missing target")?;
    let version = match parts.next().unwrap_or("HTTP/1.1") {
        "HTTP/1.0" => http::Version::HTTP_10,
        "HTTP/1.1" => http::Version::HTTP_11,
        "HTTP/2.0" => http::Version::HTTP_2,
        _ => http::Version::HTTP_11,
    };

    let method = http::Method::from_bytes(method.as_bytes())
        .with_context(|| format!("invalid request method: {method}"))?;

    let mut headers = http::HeaderMap::new();
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .context("failed to read request header line")?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading request headers");
        }
        let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n');
        if trimmed.is_empty() {
            break;
        }
        if let Some(colon_pos) = trimmed.find(':') {
            let (name, value) = trimmed.split_at(colon_pos);
            let header_name = HeaderName::from_bytes(name.trim().as_bytes())
                .with_context(|| format!("invalid request header name: {}", name.trim()))?;
            let header_value = HeaderValue::from_str(value[1..].trim()).with_context(|| {
                format!("invalid request header value for {}", name.trim())
            })?;
            headers.append(header_name, header_value);
        }
    }

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

    let mut body = BodyBuffer::default();
    if body_len > 0 {
        let mut bytes = vec![0u8; body_len];
        reader
            .read_exact(&mut bytes)
            .await
            .with_context(|| format!("expected {body_len} request body bytes, hit EOF"))?;
        body.push_bytes(&bytes);
    }

    Ok(RequestParts {
        method,
        uri,
        version,
        headers,
        body,
    })
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

fn send_http2_response(respond: &mut SendResponse<Bytes>, response: &ResponseParts) -> Result<()> {
    let head = build_http2_response_head(response)?;
    let end_stream = response.body.is_empty();
    let mut send_stream = respond
        .send_response(head, end_stream)
        .context("failed to send HTTP/2 response head")?;
    if !end_stream {
        stream_http2_body(&mut send_stream, response.body.as_bytes())?;
    }
    Ok(())
}

/// Serializes the staged HTTP/1.x response back to the client.
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

    fn new(provider: Arc<TlsProvider>) -> Self {
        Self {
            provider,
            fallback: FALLBACK_SNI.to_string(),
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
    use super::{is_benign_client_h2_shutdown, is_benign_client_h2_stream_error};

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
}
