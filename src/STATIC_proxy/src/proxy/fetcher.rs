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

use std::borrow::Cow;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use http::header::{HeaderValue, CONTENT_LENGTH, HOST};
use wreq::{
    Client, Emulation,
    header::OrigHeaderMap,
    http2::{
        Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency,
        StreamId,
    },
    redirect::Policy,
    tls::{AlpnProtocol, AlpsProtocol, ExtensionType, TlsOptions, TlsVersion},
};

use crate::{
    proxy::{BodyBuffer, Flow, RequestParts, ResponseParts},
    tls::profiles::{Http2Plan, ProfileTlsVersion, TlsClientPlan, TlsExtensionPlan},
};

#[derive(Debug, Clone)]
pub struct OriginTarget {
    pub host: String,
    pub port: u16,
}

impl OriginTarget {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamMode {
    Http1Only,
    PreferHttp2,
}

#[derive(Debug)]
pub struct OriginResponse {
    pub response: ResponseParts,
    pub upstream_protocol: String,
}

#[derive(Debug)]
pub struct StreamingOriginResponse {
    pub response: wreq::Response,
    pub upstream_protocol: String,
}

#[async_trait]
pub trait OriginFetcher: Send + Sync {
    async fn fetch(
        &self,
        flow: &Flow,
        target: &OriginTarget,
        tls_plan: Option<TlsClientPlan>,
        mode: UpstreamMode,
    ) -> Result<OriginResponse>;

    async fn fetch_streaming(
        &self,
        flow: &Flow,
        target: &OriginTarget,
        tls_plan: Option<TlsClientPlan>,
        mode: UpstreamMode,
    ) -> Result<StreamingOriginResponse>;
}

#[derive(Debug)]
pub struct WreqOriginFetcher {
    max_response_body_bytes: usize,
}

impl WreqOriginFetcher {
    pub fn new(max_response_body_bytes: usize) -> Self {
        Self {
            max_response_body_bytes,
        }
    }
}

#[async_trait]
impl OriginFetcher for WreqOriginFetcher {
    async fn fetch(
        &self,
        flow: &Flow,
        target: &OriginTarget,
        tls_plan: Option<TlsClientPlan>,
        mode: UpstreamMode,
    ) -> Result<OriginResponse> {
        match attempt_fetch(
            flow,
            target,
            tls_plan.as_ref(),
            mode,
            self.max_response_body_bytes,
        )
        .await
        {
            Ok(origin) => Ok(origin),
            Err(err) if should_retry_http1_only(tls_plan.as_ref(), mode) => {
                tracing::warn!(
                    target = %format!("{}:{}", target.host, target.port),
                    error = %format_args!("{err:#}"),
                    "preferred HTTP/2 upstream fetch failed, retrying over HTTP/1.1"
                );
                attempt_fetch(
                    flow,
                    target,
                    tls_plan.as_ref(),
                    UpstreamMode::Http1Only,
                    self.max_response_body_bytes,
                )
                .await
            }
            Err(err) => Err(err),
        }
    }

    async fn fetch_streaming(
        &self,
        flow: &Flow,
        target: &OriginTarget,
        tls_plan: Option<TlsClientPlan>,
        mode: UpstreamMode,
    ) -> Result<StreamingOriginResponse> {
        match attempt_fetch_streaming(flow, target, tls_plan.as_ref(), mode).await {
            Ok(origin) => Ok(origin),
            Err(err) if should_retry_http1_only(tls_plan.as_ref(), mode) => {
                tracing::warn!(
                    target = %format!("{}:{}", target.host, target.port),
                    error = %format_args!("{err:#}"),
                    "preferred HTTP/2 upstream fetch failed, retrying over HTTP/1.1"
                );
                attempt_fetch_streaming(
                    flow,
                    target,
                    tls_plan.as_ref(),
                    UpstreamMode::Http1Only,
                )
                .await
            }
            Err(err) => Err(err),
        }
    }
}

fn should_retry_http1_only(tls_plan: Option<&TlsClientPlan>, mode: UpstreamMode) -> bool {
    if mode != UpstreamMode::PreferHttp2 {
        return false;
    }

    tls_plan.is_none()
}

async fn attempt_fetch(
    flow: &Flow,
    target: &OriginTarget,
    tls_plan: Option<&TlsClientPlan>,
    mode: UpstreamMode,
    max_response_body_bytes: usize,
) -> Result<OriginResponse> {
    let response = send_request(flow, target, tls_plan, mode).await?;

    let upstream_protocol = negotiated_protocol_label(response.version());
    let response = response_into_parts(response, max_response_body_bytes).await?;

    Ok(OriginResponse {
        response,
        upstream_protocol,
    })
}

async fn attempt_fetch_streaming(
    flow: &Flow,
    target: &OriginTarget,
    tls_plan: Option<&TlsClientPlan>,
    mode: UpstreamMode,
) -> Result<StreamingOriginResponse> {
    let response = send_request(flow, target, tls_plan, mode).await?;
    let upstream_protocol = negotiated_protocol_label(response.version());

    Ok(StreamingOriginResponse {
        response,
        upstream_protocol,
    })
}

async fn send_request(
    flow: &Flow,
    target: &OriginTarget,
    tls_plan: Option<&TlsClientPlan>,
    mode: UpstreamMode,
) -> Result<wreq::Response> {
    let client = build_client(&flow.request, target, tls_plan, mode)?;
    let request = build_request(&client, flow, target, mode)?;
    let mode_label = match mode {
        UpstreamMode::Http1Only => "http1-only",
        UpstreamMode::PreferHttp2 => "prefer-http2",
    };
    let response = request
        .send()
        .await
        .with_context(|| {
            format!(
                "wreq fetch failed: method={} uri={} target={}:{} mode={}",
                flow.request.method,
                flow.request.uri,
                target.host,
                target.port,
                mode_label,
            )
        })?;

    Ok(response)
}

fn build_client(
    request: &RequestParts,
    target: &OriginTarget,
    tls_plan: Option<&TlsClientPlan>,
    mode: UpstreamMode,
) -> Result<Client> {
    let headers = upstream_headers(request, &target.host, target.port, mode);
    let emulation = build_emulation_provider(headers, tls_plan, mode);

    let mut builder = Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .emulation(emulation);

    if mode == UpstreamMode::Http1Only {
        builder = builder.http1_only();
    }

    builder.build().context("failed to build wreq client")
}

fn build_tls_config(plan: &TlsClientPlan, mode: UpstreamMode) -> TlsOptions {
    let alpn = select_alpn(plan, mode);
    let mut builder = TlsOptions::builder()
        .alpn_protocols(alpn.iter().copied())
        .session_ticket(plan.session_ticket())
        .pre_shared_key(plan.session_ticket())
        .psk_dhe_ke(plan.psk_dhe_ke())
        .renegotiation(plan.renegotiation())
        .enable_ocsp_stapling(plan.enable_ocsp_stapling())
        .enable_signed_cert_timestamps(plan.enable_signed_cert_timestamps())
        .enable_ech_grease(plan.enable_ech_grease())
        .min_tls_version(plan.min_tls_version().map(to_wreq_tls_version))
        .max_tls_version(plan.max_tls_version().map(to_wreq_tls_version))
        .grease_enabled(plan.grease_enabled())
        .permute_extensions(plan.permute_extensions())
        .preserve_tls13_cipher_list(plan.preserve_tls13_cipher_list())
        .record_size_limit(plan.record_size_limit());

    if let Some((alps, use_new_codepoint)) = select_alps(plan.extension_sequence(), &alpn) {
        builder = builder.alps_protocols(alps);
        if use_new_codepoint {
            builder = builder.alps_use_new_codepoint(true);
        }
    }

    if let Some(value) = plan.delegated_credentials() {
        builder = builder.delegated_credentials(Cow::Owned(value.to_string()));
    }

    if let Some(value) = cipher_list(plan) {
        builder = builder.cipher_list(Cow::Owned(value));
    }

    if let Some(value) = sigalgs_list(plan) {
        builder = builder.sigalgs_list(Cow::Owned(value));
    }

    if let Some(value) = tls_curves_list(plan) {
        builder = builder.curves_list(Cow::Owned(value));
    }

    let (extension_permutation, unsupported_extensions) =
        to_wreq_extension_permutation(plan.extension_sequence());

    if !extension_permutation.is_empty() {
        builder = builder.extension_permutation(Cow::Owned(extension_permutation));
    }

    if !unsupported_extensions.is_empty() {
        tracing::debug!(
            variant = plan.variant_id(),
            ?unsupported_extensions,
            "the current wreq adapter cannot model every TLS extension from the profile sequence; unsupported entries are omitted from explicit permutation"
        );
    }

    builder.build()
}

fn build_http2_config(plan: &Http2Plan) -> Http2Options {
    let mut builder = Http2Options::builder()
        .initial_stream_id(plan.initial_stream_id)
        .initial_connection_window_size(plan.initial_connection_window_size)
        .initial_max_send_streams(plan.initial_max_send_streams)
        .header_table_size(plan.header_table_size)
        .max_concurrent_streams(plan.max_concurrent_streams)
        .initial_window_size(plan.initial_window_size)
        .max_frame_size(plan.max_frame_size);

    if let Some(max_header_list_size) = plan.max_header_list_size {
        builder = builder.max_header_list_size(max_header_list_size);
    }

    if let Some(enable_push) = plan.enable_push {
        builder = builder.enable_push(enable_push);
    }

    if let Some(enable_connect_protocol) = plan.enable_connect_protocol {
        builder = builder.enable_connect_protocol(enable_connect_protocol);
    }

    if let Some(no_rfc7540_priorities) = plan.no_rfc7540_priorities {
        builder = builder.no_rfc7540_priorities(no_rfc7540_priorities);
    }

    if let Some(max_concurrent_reset_streams) = plan.max_concurrent_reset_streams {
        builder = builder.max_concurrent_reset_streams(max_concurrent_reset_streams);
    }

    if let Some(max_pending_accept_reset_streams) = plan.max_pending_accept_reset_streams {
        builder = builder.max_pending_accept_reset_streams(max_pending_accept_reset_streams);
    }

    if let Some(max_send_buffer_size) = plan.max_send_buffer_size {
        builder = builder.max_send_buf_size(max_send_buffer_size);
    }

    if let Some(adaptive_window) = plan.adaptive_window {
        builder = builder.adaptive_window(adaptive_window);
    }

    if let Some(dependency) = plan.headers_stream_dependency.as_ref() {
        builder = builder.headers_stream_dependency(to_wreq_stream_dependency(dependency));
    }

    if let Some(order) = to_wreq_pseudo_order(&plan.pseudo_header_order) {
        builder = builder.headers_pseudo_order(order);
    }

    if let Some(order) = to_wreq_settings_order(&plan.settings_order) {
        builder = builder.settings_order(order);
    }

    builder.build()
}

fn apply_emulation_options(
    mut builder: wreq::EmulationBuilder,
    tls_config: Option<TlsOptions>,
    http2_config: Option<Http2Options>,
) -> wreq::EmulationBuilder {
    if let Some(tls_config) = tls_config {
        builder = builder.tls_options(tls_config);
    }

    if let Some(http2_config) = http2_config {
        builder = builder.http2_options(http2_config);
    }

    builder
}

fn build_request(
    client: &Client,
    flow: &Flow,
    target: &OriginTarget,
    mode: UpstreamMode,
) -> Result<wreq::RequestBuilder> {
    let url = origin_url(&flow.request, target);
    let method = flow.request.method.clone();
    let mut request = client.request(method, &url);

    if mode == UpstreamMode::Http1Only {
        request = request.version(http::Version::HTTP_11);
    }
    if !flow.request.body.is_empty() {
        request = request.body(flow.request.body.as_bytes().to_vec());
    }

    Ok(request)
}

fn build_emulation_provider(
    headers: http::HeaderMap,
    tls_plan: Option<&TlsClientPlan>,
    mode: UpstreamMode,
) -> Emulation {
    let tls_config = tls_plan.map(|plan| build_tls_config(plan, mode));
    let http2_config = if mode != UpstreamMode::Http1Only && tls_plan.map(plan_supports_h2_upstream).unwrap_or(true) {
        tls_plan.and_then(|plan| plan.http2()).map(build_http2_config)
    } else {
        None
    };

    apply_emulation_options(
        Emulation::builder()
        .headers(headers.clone())
        .orig_headers(header_order(&headers)),
        tls_config,
        http2_config,
    )
    .build()
}

fn origin_url(request: &RequestParts, target: &OriginTarget) -> String {
    let authority = if target.port == 443 {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let path = request
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    format!("https://{}{}", authority, path)
}

const REQUEST_HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

fn upstream_headers(
    request: &RequestParts,
    host: &str,
    port: u16,
    mode: UpstreamMode,
) -> http::HeaderMap {
    let mut headers = request.headers.clone();

    for header in REQUEST_HOP_BY_HOP_HEADERS {
        headers.remove(*header);
    }

    reconcile_request_body_headers(&mut headers, request);

    if mode != UpstreamMode::Http1Only {
        headers.remove(HOST);
        return headers;
    }

    if headers.contains_key(HOST) {
        return headers;
    }

    let host_value = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };

    match HeaderValue::from_str(&host_value) {
        Ok(value) => {
            headers.insert(HOST, value);
        }
        Err(err) => {
            tracing::warn!(host = %host_value, ?err, "failed to synthesize Host header for upstream request");
        }
    }

    headers
}

fn reconcile_request_body_headers(headers: &mut http::HeaderMap, request: &RequestParts) {
    if request.body.is_empty() {
        headers.remove(CONTENT_LENGTH);
        return;
    }

    match HeaderValue::from_str(&request.body.len().to_string()) {
        Ok(value) => {
            headers.insert(CONTENT_LENGTH, value);
        }
        Err(err) => {
            tracing::warn!(len = request.body.len(), ?err, "failed to normalize request Content-Length after body mutation");
            headers.remove(CONTENT_LENGTH);
        }
    }
}

fn header_order(headers: &http::HeaderMap) -> OrigHeaderMap {
    let mut ordered = OrigHeaderMap::with_capacity(headers.len());
    for name in headers.keys() {
        ordered.insert(name.clone());
    }
    ordered
}

async fn response_into_parts(response: wreq::Response, max_response_body_bytes: usize) -> Result<ResponseParts> {
    let status = response.status();
    let version = response.version();
    if let Some(content_length) = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
    {
        if content_length > max_response_body_bytes {
            return Err(anyhow!(
                "upstream response body exceeds configured limit of {max_response_body_bytes} bytes"
            ));
        }
    }
    let headers = response.headers().clone();
    let bytes = response
        .bytes()
        .await
        .context("failed to buffer upstream response body")?;

    if bytes.len() > max_response_body_bytes {
        return Err(anyhow!(
            "upstream response body exceeds configured limit of {max_response_body_bytes} bytes"
        ));
    }

    let mut body = BodyBuffer::default();
    body.push_bytes_limited(bytes.as_ref(), max_response_body_bytes, "upstream response body")?;

    Ok(ResponseParts {
        status,
        version,
        headers,
        body,
    })
}

fn negotiated_protocol_label(version: http::Version) -> String {
    match version {
        http::Version::HTTP_2 => "h2".to_string(),
        http::Version::HTTP_10 => "http/1.0".to_string(),
        _ => "http/1.1".to_string(),
    }
}

fn cipher_list(plan: &TlsClientPlan) -> Option<String> {
    if plan.cipher_suites().is_empty() {
        None
    } else {
        Some(plan.cipher_suites().join(":"))
    }
}

fn to_wreq_tls_version(version: ProfileTlsVersion) -> TlsVersion {
    match version {
        ProfileTlsVersion::Tls12 => TlsVersion::TLS_1_2,
        ProfileTlsVersion::Tls13 => TlsVersion::TLS_1_3,
    }
}

fn select_alpn(plan: &TlsClientPlan, mode: UpstreamMode) -> Vec<AlpnProtocol> {
    if mode == UpstreamMode::Http1Only {
        return vec![AlpnProtocol::HTTP1];
    }

    if plan
        .alpn_protocols()
        .iter()
        .any(|value| value.eq_ignore_ascii_case("h3"))
    {
        tracing::debug!(
            variant = plan.variant_id(),
            "profile requested h3 ALPN but the current outbound adapter only negotiates h2/http/1.1 over TCP"
        );
    }

    let has_h2 = plan
        .alpn_protocols()
        .iter()
        .any(|value| value.eq_ignore_ascii_case("h2"));
    let has_http1 = plan
        .alpn_protocols()
        .iter()
        .any(|value| value.eq_ignore_ascii_case("http/1.1"));

    match (has_h2, has_http1) {
        (true, false) => vec![AlpnProtocol::HTTP2],
        (true, true) => vec![AlpnProtocol::HTTP2, AlpnProtocol::HTTP1],
        _ => vec![AlpnProtocol::HTTP1],
    }
}

fn sigalgs_list(plan: &TlsClientPlan) -> Option<String> {
    if plan.signature_algorithms().is_empty() {
        None
    } else {
        Some(plan.signature_algorithms().join(":"))
    }
}

fn tls_curves_list(plan: &TlsClientPlan) -> Option<String> {
    let groups = if !plan.key_share_order().is_empty() {
        plan.key_share_order()
    } else {
        plan.supported_groups()
    };

    let curves = groups
        .iter()
        .filter_map(|group| to_wreq_curve_name(group))
        .collect::<Vec<_>>();

    if curves.is_empty() {
        None
    } else {
        Some(curves.join(":"))
    }
}

fn select_alps(
    extension_sequence: &[TlsExtensionPlan],
    alpn: &[AlpnProtocol],
) -> Option<(Vec<AlpsProtocol>, bool)> {
    let application_settings = extension_sequence
        .iter()
        .find(|extension| extension.name().eq_ignore_ascii_case("application_settings"));

    let Some(application_settings) = application_settings else {
        return None;
    };

    let mut alps = Vec::new();
    if alpn.contains(&AlpnProtocol::HTTP2) {
        alps.push(AlpsProtocol::HTTP2);
    }
    if alpn.contains(&AlpnProtocol::HTTP1) {
        alps.push(AlpsProtocol::HTTP1);
    }

    if alps.is_empty() {
        return None;
    }

    Some((
        alps,
        matches!(
            application_settings.code().map(ExtensionType::from),
            Some(code) if code == ExtensionType::APPLICATION_SETTINGS_NEW
        ),
    ))
}

fn to_wreq_extension_permutation(sequence: &[TlsExtensionPlan]) -> (Vec<ExtensionType>, Vec<String>) {
    let mut mapped = Vec::new();
    let mut unsupported = Vec::new();

    for extension in sequence {
        match to_wreq_extension_type(extension) {
            Some(extension_type) => mapped.push(extension_type),
            None if extension.name().eq_ignore_ascii_case("grease") => {}
            None => unsupported.push(extension.name().to_string()),
        }
    }

    (mapped, unsupported)
}

fn to_wreq_extension_type(extension: &TlsExtensionPlan) -> Option<ExtensionType> {
    if let Some(code) = extension.code() {
        return Some(ExtensionType::from(code));
    }

    match extension.name().to_ascii_lowercase().as_str() {
        "server_name" => Some(ExtensionType::SERVER_NAME),
        "extended_master_secret" => Some(ExtensionType::EXTENDED_MASTER_SECRET),
        "renegotiation_info" => Some(ExtensionType::RENEGOTIATE),
        "supported_groups" => Some(ExtensionType::SUPPORTED_GROUPS),
        "ec_point_formats" => Some(ExtensionType::EC_POINT_FORMATS),
        "session_ticket" => Some(ExtensionType::SESSION_TICKET),
        "application_layer_protocol_negotiation" => {
            Some(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        }
        "application_settings" => Some(ExtensionType::APPLICATION_SETTINGS),
        "status_request" => Some(ExtensionType::STATUS_REQUEST),
        "delegated_credential" | "delegated_credentials" => {
            Some(ExtensionType::DELEGATED_CREDENTIAL)
        }
        "signed_certificate_timestamp" | "certificate_timestamp" => {
            Some(ExtensionType::CERTIFICATE_TIMESTAMP)
        }
        "key_share" => Some(ExtensionType::KEY_SHARE),
        "supported_versions" => Some(ExtensionType::SUPPORTED_VERSIONS),
        "signature_algorithms" => Some(ExtensionType::SIGNATURE_ALGORITHMS),
        "psk_key_exchange_modes" => Some(ExtensionType::PSK_KEY_EXCHANGE_MODES),
        "record_size_limit" => Some(ExtensionType::RECORD_SIZE_LIMIT),
        "compress_certificate" | "certificate_compression" => {
            Some(ExtensionType::CERT_COMPRESSION)
        }
        "encrypted_client_hello" | "ech" => Some(ExtensionType::ENCRYPTED_CLIENT_HELLO),
        "padding" => Some(ExtensionType::PADDING),
        _ => None,
    }
}

fn to_wreq_curve_name(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "x25519" => Some("X25519"),
        "secp256r1" | "p256" => Some("P-256"),
        "secp384r1" | "p384" => Some("P-384"),
        "secp521r1" | "p521" => Some("P-521"),
        "x25519mlkem768" => Some("X25519MLKEM768"),
        other => {
            tracing::debug!(curve = other, "unsupported wreq curve in profile");
            None
        }
    }
}

fn to_wreq_stream_dependency(
    dependency: &crate::tls::profiles::Http2StreamDependencyPlan,
) -> StreamDependency {
    let stream_id = if dependency.stream_id == 0 {
        StreamId::ZERO
    } else {
        StreamId::from(dependency.stream_id)
    };

    StreamDependency::new(stream_id, dependency.weight, dependency.exclusive)
}

fn to_wreq_pseudo_id(name: &str) -> Option<PseudoId> {
    match name.to_ascii_lowercase().as_str() {
        "method" => Some(PseudoId::Method),
        "scheme" => Some(PseudoId::Scheme),
        "authority" => Some(PseudoId::Authority),
        "path" => Some(PseudoId::Path),
        "protocol" => Some(PseudoId::Protocol),
        "status" => Some(PseudoId::Status),
        other => {
            tracing::debug!(pseudo = other, "unsupported wreq pseudo-header id in profile");
            None
        }
    }
}

fn to_wreq_setting_id(name: &str) -> Option<SettingId> {
    match name.to_ascii_lowercase().as_str() {
        "header_table_size" => Some(SettingId::HeaderTableSize),
        "enable_push" => Some(SettingId::EnablePush),
        "max_concurrent_streams" => Some(SettingId::MaxConcurrentStreams),
        "initial_window_size" => Some(SettingId::InitialWindowSize),
        "max_frame_size" => Some(SettingId::MaxFrameSize),
        "max_header_list_size" => Some(SettingId::MaxHeaderListSize),
        "enable_connect_protocol" => Some(SettingId::EnableConnectProtocol),
        "no_rfc7540_priorities" => Some(SettingId::NoRfc7540Priorities),
        other => {
            tracing::debug!(setting = other, "unsupported wreq HTTP/2 setting id in profile");
            None
        }
    }
}

fn to_wreq_pseudo_order(order: &[String]) -> Option<PseudoOrder> {
    if order.is_empty() {
        return None;
    }

    Some(
        PseudoOrder::builder()
            .extend(order.iter().filter_map(|name| to_wreq_pseudo_id(name)))
            .build(),
    )
}

fn to_wreq_settings_order(order: &[String]) -> Option<SettingsOrder> {
    if order.is_empty() {
        return None;
    }

    Some(
        SettingsOrder::builder()
            .extend(order.iter().filter_map(|name| to_wreq_setting_id(name)))
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        build_http2_config, plan_supports_h2_upstream, select_alpn, select_alps, should_retry_http1_only,
        to_wreq_extension_permutation, to_wreq_pseudo_id, to_wreq_setting_id, upstream_headers, UpstreamMode,
    };
    use crate::proxy::{BodyBuffer, RequestParts};
    use crate::tls::profiles::{Http2Plan, TlsClientPlan, TlsExtensionPlan};
    use http::header::{CONTENT_LENGTH, HOST};
    use http::{HeaderMap, HeaderValue, Method, Uri, Version};
    use wreq::{
        http2::{PseudoId, SettingId},
        tls::{AlpnProtocol, AlpsProtocol, ExtensionType},
    };

    fn sample_tls_plan(alpn: Vec<&str>) -> TlsClientPlan {
        TlsClientPlan::test_fixture(alpn.into_iter().map(str::to_string).collect())
    }

    #[test]
    fn select_alpn_prefers_http2_and_http11_only() {
        let plan = sample_tls_plan(vec!["h3", "h2", "http/1.1"]);

        assert_eq!(select_alpn(&plan, UpstreamMode::PreferHttp2), vec![AlpnProtocol::HTTP2, AlpnProtocol::HTTP1]);
        assert_eq!(select_alpn(&plan, UpstreamMode::Http1Only), vec![AlpnProtocol::HTTP1]);
    }

    #[test]
    fn plan_supports_h2_upstream_only_when_h2_is_advertised() {
        let h2_plan = TlsClientPlan::test_fixture(vec!["h2".into(), "http/1.1".into()]);
        let h1_plan = TlsClientPlan::test_fixture(vec!["http/1.1".into()]);

        assert!(plan_supports_h2_upstream(&h2_plan));
        assert!(!plan_supports_h2_upstream(&h1_plan));
    }

    #[test]
    fn http2_retry_only_applies_without_a_tls_plan() {
        let h2_plan = TlsClientPlan::test_fixture(vec!["h2".into(), "http/1.1".into()]);

        assert!(should_retry_http1_only(None, UpstreamMode::PreferHttp2));
        assert!(!should_retry_http1_only(Some(&h2_plan), UpstreamMode::PreferHttp2));
        assert!(!should_retry_http1_only(Some(&h2_plan), UpstreamMode::Http1Only));
    }

    #[test]
    fn http2_plan_type_remains_constructible_for_fetcher_tests() {
        let plan = Http2Plan {
            initial_stream_id: Some(1),
            initial_window_size: Some(65535),
            initial_connection_window_size: Some(1_048_576),
            initial_max_send_streams: Some(100),
            max_frame_size: Some(16384),
            max_header_list_size: Some(65536),
            header_table_size: Some(65536),
            enable_push: Some(false),
            enable_connect_protocol: Some(false),
            no_rfc7540_priorities: Some(false),
            max_concurrent_streams: Some(1000),
            max_concurrent_reset_streams: Some(8),
            max_pending_accept_reset_streams: Some(4),
            max_send_buffer_size: Some(131072),
            adaptive_window: Some(false),
            pseudo_header_order: vec!["method".into(), "path".into(), "authority".into(), "scheme".into()],
            settings_order: vec![
                "header_table_size".into(),
                "enable_push".into(),
                "max_concurrent_streams".into(),
                "initial_window_size".into(),
                "max_frame_size".into(),
                "max_header_list_size".into(),
                "enable_connect_protocol".into(),
                "no_rfc7540_priorities".into(),
            ],
            headers_stream_dependency: None,
        };

        assert_eq!(plan.initial_stream_id, Some(1));
    }

    #[test]
    fn wreq6_pseudo_and_setting_ids_map_from_profile_names() {
        assert_eq!(to_wreq_pseudo_id("method"), Some(PseudoId::Method));
        assert_eq!(to_wreq_pseudo_id("scheme"), Some(PseudoId::Scheme));
        assert_eq!(to_wreq_setting_id("enable_connect_protocol"), Some(SettingId::EnableConnectProtocol));
        assert_eq!(to_wreq_setting_id("no_rfc7540_priorities"), Some(SettingId::NoRfc7540Priorities));
    }

    #[test]
    fn build_http2_config_preserves_supported_wreq6_fields() {
        let plan = Http2Plan {
            initial_stream_id: Some(1),
            initial_window_size: Some(65535),
            initial_connection_window_size: Some(1_048_576),
            initial_max_send_streams: Some(100),
            max_frame_size: Some(16384),
            max_header_list_size: Some(65536),
            header_table_size: Some(65536),
            enable_push: Some(false),
            enable_connect_protocol: Some(true),
            no_rfc7540_priorities: Some(true),
            max_concurrent_streams: Some(1000),
            max_concurrent_reset_streams: Some(8),
            max_pending_accept_reset_streams: Some(4),
            max_send_buffer_size: Some(131072),
            adaptive_window: Some(false),
            pseudo_header_order: vec!["method".into(), "path".into(), "authority".into(), "scheme".into()],
            settings_order: vec![
                "header_table_size".into(),
                "enable_push".into(),
                "max_concurrent_streams".into(),
                "initial_window_size".into(),
                "max_frame_size".into(),
                "max_header_list_size".into(),
                "enable_connect_protocol".into(),
                "no_rfc7540_priorities".into(),
            ],
            headers_stream_dependency: None,
        };

        let options = build_http2_config(&plan);

        assert_eq!(options.initial_stream_id, Some(1));
        assert_eq!(options.initial_max_send_streams, 100);
        assert_eq!(options.enable_connect_protocol, Some(true));
        assert_eq!(options.no_rfc7540_priorities, Some(true));
        assert!(options.headers_pseudo_order.is_some());
        assert!(options.settings_order.is_some());
    }

    #[test]
    fn tls_extension_sequence_maps_to_wreq_permutation() {
        let (mapped, unsupported) = to_wreq_extension_permutation(&[
            TlsExtensionPlan::from_parts(Some(0x6a6a), "grease"),
            TlsExtensionPlan::from_parts(Some(0x0000), "server_name"),
            TlsExtensionPlan::from_parts(Some(0x445c), "application_settings"),
            TlsExtensionPlan::from_parts(Some(0x0031), "post_handshake_auth"),
            TlsExtensionPlan::from_parts(Some(0xfe0d), "padding"),
        ]);

        assert_eq!(
            mapped,
            vec![
                ExtensionType::SERVER_NAME,
                ExtensionType::from(0x445c),
                ExtensionType::from(0x0031),
                ExtensionType::PADDING,
            ]
        );
        assert!(unsupported.is_empty());
    }

    #[test]
    fn application_settings_enables_alps_for_selected_h2() {
        let alps = select_alps(
            &[TlsExtensionPlan::from_parts(Some(0x445c), "application_settings")],
            &[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1],
        )
        .expect("alps should be enabled when application_settings is requested");

        assert_eq!(alps.0, vec![AlpsProtocol::HTTP2, AlpsProtocol::HTTP1]);
        assert!(!alps.1);
    }

    #[test]
    fn upstream_headers_recompute_content_length_after_body_mutation() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("3"));
        headers.insert(HOST, HeaderValue::from_static("example.com"));

        let mut body = BodyBuffer::default();
        body.replace(b"hello world");

        let request = RequestParts {
            method: Method::POST,
            uri: Uri::from_static("https://example.com/session"),
            version: Version::HTTP_11,
            headers,
            body,
        };

        let normalized = upstream_headers(&request, "example.com", 443, UpstreamMode::Http1Only);

        assert_eq!(
            normalized
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("11")
        );
    }

    #[test]
    fn upstream_headers_drop_stale_content_length_for_empty_body() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("99"));

        let request = RequestParts {
            method: Method::GET,
            uri: Uri::from_static("https://example.com/"),
            version: Version::HTTP_11,
            headers,
            body: BodyBuffer::default(),
        };

        let normalized = upstream_headers(&request, "example.com", 443, UpstreamMode::PreferHttp2);

        assert!(normalized.get(CONTENT_LENGTH).is_none());
    }

}

pub fn plan_supports_h2_upstream(plan: &TlsClientPlan) -> bool {
    plan
        .alpn_protocols()
        .iter()
        .any(|value| value.eq_ignore_ascii_case("h2"))
}