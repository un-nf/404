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

use anyhow::{Context, Result};
use async_trait::async_trait;
use http::header::{HeaderValue, HOST};
use wreq::{
    AlpnProtos, Client, EmulationProvider, Http2Config, PseudoOrder, SettingsOrder, SslCurve,
    StreamDependency, StreamId, TlsConfig,
    redirect::Policy,
    tls::TlsVersion,
};

use crate::{
    proxy::{BodyBuffer, Flow, RequestParts, ResponseParts},
    tls::profiles::{Http2Plan, ProfileTlsVersion, TlsClientPlan},
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

#[async_trait]
pub trait OriginFetcher: Send + Sync {
    async fn fetch(
        &self,
        flow: &Flow,
        target: &OriginTarget,
        tls_plan: Option<TlsClientPlan>,
        mode: UpstreamMode,
    ) -> Result<OriginResponse>;
}

#[derive(Debug, Default)]
pub struct WreqOriginFetcher;

impl WreqOriginFetcher {
    pub fn new() -> Self {
        Self
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
        match attempt_fetch(flow, target, tls_plan.as_ref(), mode).await {
            Ok(origin) => Ok(origin),
            Err(err) if mode == UpstreamMode::PreferHttp2 => {
                tracing::warn!(
                    target = %format!("{}:{}", target.host, target.port),
                    error = %format_args!("{err:#}"),
                    "preferred HTTP/2 upstream fetch failed, retrying over HTTP/1.1"
                );
                attempt_fetch(flow, target, tls_plan.as_ref(), UpstreamMode::Http1Only).await
            }
            Err(err) => Err(err),
        }
    }
}

async fn attempt_fetch(
    flow: &Flow,
    target: &OriginTarget,
    tls_plan: Option<&TlsClientPlan>,
    mode: UpstreamMode,
) -> Result<OriginResponse> {
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

    let upstream_protocol = negotiated_protocol_label(response.version());
    let response = response_into_parts(response).await?;

    Ok(OriginResponse {
        response,
        upstream_protocol,
    })
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

fn build_tls_config(plan: &TlsClientPlan, mode: UpstreamMode) -> TlsConfig {
    let mut config = TlsConfig::default();
    config.alpn_protos = select_alpn(plan, mode);
    config.session_ticket = plan.session_ticket();
    config.pre_shared_key = plan.session_ticket();
    config.psk_dhe_ke = plan.psk_dhe_ke();
    config.renegotiation = plan.renegotiation();
    config.enable_ocsp_stapling = plan.enable_ocsp_stapling();
    config.enable_signed_cert_timestamps = plan.enable_signed_cert_timestamps();
    config.enable_ech_grease = plan.enable_ech_grease();
    config.min_tls_version = plan.min_tls_version().map(to_wreq_tls_version);
    config.max_tls_version = plan.max_tls_version().map(to_wreq_tls_version);
    config.grease_enabled = plan.grease_enabled();
    config.permute_extensions = plan.permute_extensions();
    config.record_size_limit = plan.record_size_limit();
    config.delegated_credentials = plan
        .delegated_credentials()
        .map(|value| Cow::Owned(value.to_string()));
    config.cipher_list = cipher_list(plan).map(Cow::Owned);
    config.sigalgs_list = sigalgs_list(plan).map(Cow::Owned);

    let curves = tls_curves(plan);
    if !curves.is_empty() {
        config.curves = Some(Cow::Owned(curves));
    }

    if !plan.extension_sequence().is_empty() {
        tracing::debug!(
            variant = plan.variant_id(),
            "wreq 5.3 does not expose explicit TLS extension ordering by extension type; keeping permutation flags only"
        );
    }

    config
}

fn build_http2_config(plan: &Http2Plan) -> Http2Config {
    let pseudo_order = to_wreq_pseudo_order(&plan.pseudo_header_order);
    let settings_order = to_wreq_settings_order(&plan.settings_order);

    let builder = Http2Config::builder()
        .initial_stream_id(plan.initial_stream_id)
        .initial_connection_window_size(plan.initial_connection_window_size)
        .header_table_size(plan.header_table_size)
        .enable_push(plan.enable_push)
        .max_concurrent_streams(plan.max_concurrent_streams)
        .initial_stream_window_size(plan.initial_window_size)
        .max_frame_size(plan.max_frame_size)
        .max_header_list_size(plan.max_header_list_size)
        .unknown_setting8(plan.enable_connect_protocol)
        .unknown_setting9(plan.no_rfc7540_priorities)
        .headers_priority(plan.headers_stream_dependency.as_ref().map(to_wreq_stream_dependency))
        .headers_pseudo_order(pseudo_order);

    match settings_order {
        Some(settings_order) => builder.settings_order(settings_order).build(),
        None => builder.build(),
    }
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
) -> EmulationProvider {
    let tls_config = tls_plan.map(|plan| build_tls_config(plan, mode));
    let http2_config = if mode != UpstreamMode::Http1Only {
        tls_plan.and_then(|plan| plan.http2()).map(build_http2_config)
    } else {
        None
    };

    EmulationProvider::builder()
        .default_headers(headers.clone())
        .headers_order(header_order(&headers))
        .tls_config(tls_config)
        .http2_config(http2_config)
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

fn header_order(headers: &http::HeaderMap) -> Vec<http::header::HeaderName> {
    headers.keys().cloned().collect()
}

async fn response_into_parts(response: wreq::Response) -> Result<ResponseParts> {
    let status = response.status();
    let version = response.version();
    let headers = response.headers().clone();
    let bytes = response
        .bytes()
        .await
        .context("failed to buffer upstream response body")?;

    let mut body = BodyBuffer::default();
    body.push_bytes(bytes.as_ref());

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

fn select_alpn(plan: &TlsClientPlan, mode: UpstreamMode) -> AlpnProtos {
    if mode == UpstreamMode::Http1Only {
        return AlpnProtos::HTTP1;
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
        (true, false) => AlpnProtos::HTTP2,
        (true, true) => AlpnProtos::ALL,
        _ => AlpnProtos::HTTP1,
    }
}

fn sigalgs_list(plan: &TlsClientPlan) -> Option<String> {
    if plan.signature_algorithms().is_empty() {
        None
    } else {
        Some(plan.signature_algorithms().join(":"))
    }
}

fn tls_curves(plan: &TlsClientPlan) -> Vec<SslCurve> {
    let groups = if !plan.key_share_order().is_empty() {
        plan.key_share_order()
    } else {
        plan.supported_groups()
    };

    groups
        .iter()
        .filter_map(|group| to_wreq_curve(group))
        .collect()
}

fn to_wreq_curve(name: &str) -> Option<SslCurve> {
    match name.to_ascii_lowercase().as_str() {
        "x25519" => Some(SslCurve::X25519),
        "secp256r1" | "p256" => Some(SslCurve::SECP256R1),
        "secp384r1" | "p384" => Some(SslCurve::SECP384R1),
        "secp521r1" | "p521" => Some(SslCurve::SECP521R1),
        "x25519mlkem768" => Some(SslCurve::X25519_MLKEM768),
        other => {
            tracing::debug!(curve = other, "unsupported wreq curve in profile");
            None
        }
    }
}

fn to_wreq_pseudo_id(name: &str) -> Option<PseudoOrder> {
    match name.to_ascii_lowercase().as_str() {
        "method" | ":method" => Some(PseudoOrder::Method),
        "path" | ":path" => Some(PseudoOrder::Path),
        "authority" | ":authority" => Some(PseudoOrder::Authority),
        "scheme" | ":scheme" => Some(PseudoOrder::Scheme),
        other => {
            tracing::debug!(pseudo = other, "unsupported HTTP/2 pseudo-header id in profile");
            None
        }
    }
}

fn to_wreq_setting_id(name: &str) -> Option<SettingsOrder> {
    match name.to_ascii_lowercase().as_str() {
        "header_table_size" => Some(SettingsOrder::HeaderTableSize),
        "enable_push" => Some(SettingsOrder::EnablePush),
        "max_concurrent_streams" => Some(SettingsOrder::MaxConcurrentStreams),
        "initial_window_size" => Some(SettingsOrder::InitialWindowSize),
        "max_frame_size" => Some(SettingsOrder::MaxFrameSize),
        "max_header_list_size" => Some(SettingsOrder::MaxHeaderListSize),
        "enable_connect_protocol" => Some(SettingsOrder::UnknownSetting8),
        "no_rfc7540_priorities" => Some(SettingsOrder::UnknownSetting9),
        other => {
            tracing::debug!(setting = other, "unsupported HTTP/2 setting id in profile");
            None
        }
    }
}

fn to_wreq_pseudo_order(order: &[String]) -> Option<[PseudoOrder; 4]> {
    let mapped = order
        .iter()
        .filter_map(|item| to_wreq_pseudo_id(item))
        .collect::<Vec<_>>();

    if !order.is_empty() && mapped.len() != 4 {
        tracing::debug!(?order, "incomplete HTTP/2 pseudo-header order; leaving wreq default ordering in place");
    }

    mapped.try_into().ok()
}

fn to_wreq_settings_order(order: &[String]) -> Option<[SettingsOrder; 8]> {
    let mapped = order
        .iter()
        .filter_map(|item| to_wreq_setting_id(item))
        .collect::<Vec<_>>();

    if !order.is_empty() && mapped.len() != 8 {
        tracing::debug!(?order, "incomplete HTTP/2 settings order; leaving wreq default ordering in place");
    }

    mapped.try_into().ok()
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

#[cfg(test)]
mod tests {
    use super::{select_alpn, to_wreq_pseudo_order, to_wreq_settings_order, AlpnProtos, UpstreamMode};
    use crate::tls::profiles::{Http2Plan, TlsClientPlan};

    fn sample_tls_plan(alpn: Vec<&str>) -> TlsClientPlan {
        TlsClientPlan::test_fixture(alpn.into_iter().map(str::to_string).collect())
    }

    #[test]
    fn select_alpn_prefers_http2_and_http11_only() {
        let plan = sample_tls_plan(vec!["h3", "h2", "http/1.1"]);

        assert_eq!(select_alpn(&plan, UpstreamMode::PreferHttp2), AlpnProtos::ALL);
        assert_eq!(select_alpn(&plan, UpstreamMode::Http1Only), AlpnProtos::HTTP1);
    }

    #[test]
    fn to_wreq_pseudo_order_requires_complete_mapping() {
        let complete = vec![":method".to_string(), ":path".to_string(), ":authority".to_string(), ":scheme".to_string()];
        let incomplete = vec![":method".to_string(), ":path".to_string(), "bogus".to_string()];

        assert!(to_wreq_pseudo_order(&complete).is_some());
        assert!(to_wreq_pseudo_order(&incomplete).is_none());
    }

    #[test]
    fn to_wreq_settings_order_requires_complete_mapping() {
        let complete = vec![
            "header_table_size".to_string(),
            "enable_push".to_string(),
            "max_concurrent_streams".to_string(),
            "initial_window_size".to_string(),
            "max_frame_size".to_string(),
            "max_header_list_size".to_string(),
            "enable_connect_protocol".to_string(),
            "no_rfc7540_priorities".to_string(),
        ];
        let incomplete = vec![
            "header_table_size".to_string(),
            "enable_push".to_string(),
            "bogus".to_string(),
        ];

        assert!(to_wreq_settings_order(&complete).is_some());
        assert!(to_wreq_settings_order(&incomplete).is_none());
    }

    #[test]
    fn http2_plan_type_remains_constructible_for_fetcher_tests() {
        let plan = Http2Plan {
            initial_stream_id: Some(1),
            initial_window_size: Some(65535),
            initial_connection_window_size: Some(1_048_576),
            initial_max_send_streams: None,
            max_frame_size: Some(16384),
            max_header_list_size: Some(65536),
            header_table_size: Some(65536),
            enable_push: Some(false),
            enable_connect_protocol: Some(false),
            no_rfc7540_priorities: Some(false),
            max_concurrent_streams: Some(1000),
            max_concurrent_reset_streams: None,
            max_pending_accept_reset_streams: None,
            max_send_buffer_size: None,
            adaptive_window: None,
            pseudo_header_order: vec![],
            settings_order: vec![],
            headers_stream_dependency: None,
        };

        assert_eq!(plan.initial_stream_id, Some(1));
    }
}