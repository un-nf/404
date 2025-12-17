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

use crate::behavior::BehavioralNoisePlan;
use bytes::BytesMut;
use http::{header::HeaderName, HeaderMap, Method, Uri, Version};
use serde_json::Value;
use uuid::Uuid;

/// Flow tracks everything we know about a single HTTP request/response pair as it moves
/// through the STATIC pipeline. Each HTTP/1.1 request or HTTP/2 stream gets its own Flow
/// so stages can mutate headers, bodies, and metadata without touching other traffic.
///
/// A Flow is created immediately after the TLS handshake, populated with the parsed
/// request, run through the stage pipeline, forwarded upstream, and finally logged once
/// the downstream response is delivered. Flows are owned by a single task, so mutating
/// them with `&mut` is safe without extra synchronization.
#[derive(Debug)]
pub struct Flow {
    /// Unique identifier for this request/response pair (UUID v7 = timestamp-sortable).
    /// Used for tracing, logging, and correlating telemetry events.
    pub id: Uuid,

    /// Parsed HTTP request from the client (method, URI, headers, body).
    pub request: RequestParts,

    /// Parsed HTTP response from upstream (status, headers, body).
    /// None until the upstream response arrives (or if the request fails before reaching upstream).
    pub response: Option<ResponseParts>,

    /// Cross-stage metadata scratchpad (TLS SNI, profile selection, CSP nonces, etc.).
    /// Stages write to this to communicate with each other and with telemetry.
    pub metadata: FlowMetadata,
}

impl Flow {
    /// Creates a new Flow for the given request.
    ///
    /// **UUID v7:**
    /// Uuid::now_v7() generates a time-ordered UUID (sortable by creation time), which is
    /// useful for tracing and log correlation. Unlike v4 (random), v7 UUIDs reveal rough
    /// temporal ordering without needing a separate timestamp field.
    pub fn new(request: RequestParts) -> Self {
        Self {
            id: Uuid::now_v7(),
            request,
            response: None,
            metadata: FlowMetadata::default(),
        }
    }
}

/// Parsed HTTP request components (method, URI, version, headers, body).
///
/// **Purpose:**
/// Provides a mutable, owned representation of the client's HTTP request that pipeline
/// stages can inspect and modify. Mirrors hyper's Request type but with owned data for
/// easier mutation across async stage boundaries.
///
/// We keep an owned version of the HTTP request rather than hyper's streaming `Body` so
/// stages can edit data without juggling lifetimes or async readers. Parsing already
/// fills these fields with the real method, URI, headers, and buffered body.
#[derive(Debug)]
pub struct RequestParts {

    pub method: Method,

    pub uri: Uri,

    pub version: Version,

    pub headers: HeaderMap,

    pub body: BodyBuffer,
}

impl Default for RequestParts {
    /// Placeholder request for testing/development before HTTP parsing lands.
    fn default() -> Self {
        Self {
            method: Method::GET,
            uri: Uri::from_static("http://example"),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: BodyBuffer::default(),
        }
    }
}

/// Parsed HTTP response components (status, version, headers, body).
#[derive(Debug, Default)]
pub struct ResponseParts {

    pub status: http::StatusCode,
    
    pub version: Version,
   
    pub headers: HeaderMap,

    pub body: BodyBuffer,
}

/// Growable byte buffer for HTTP request/response bodies.
///
/// Bodies are currently fully buffered in memory via `BytesMut`, which keeps stage logic
/// simple (no streaming state machines) at the cost of higher memory usage on very large
/// payloads. We can revisit this once streaming transformations land.
#[derive(Debug, Default)]
pub struct BodyBuffer {
    /// Internal buffer using BytesMut for efficient growth.
    /// BytesMut pre-allocates capacity and uses copy-on-write for slicing.
    data: BytesMut,
}

impl BodyBuffer {
    /// Appends a byte slice to the buffer. BytesMut handles growth internally so most
    /// appends are a memcpy against pre-allocated capacity.
    pub fn push_bytes(&mut self, chunk: &[u8]) {
        self.data.extend_from_slice(chunk);
    }

    /// Returns a read-only view of the buffered data so stages can inspect payloads.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the number of bytes currently buffered.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Replaces the buffer with new contents.
    pub fn replace(&mut self, chunk: &[u8]) {
        self.data.clear();
        self.data.extend_from_slice(chunk);
    }

    /// Returns true when no bytes are buffered.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// FlowMetadata is a typed scratchpad for stages to communicate (CSP nonce handoffs,
/// profile selections, protocol labels) and for telemetry to record the final state of
/// the flow without poking at stage internals.
#[derive(Debug, Default)]
pub struct FlowMetadata {

    pub tls_sni: Option<String>,

    pub connect_target: Option<String>,

    pub profile_name: Option<String>,

    pub browser_profile: Option<String>,

    pub user_agent: Option<String>,

    pub fingerprint_config: Value,

    pub csp_nonce: Option<String>,

    pub script_hashes: Vec<String>,

    pub alt_svc_mutations: Vec<String>,

    /// Registrable domain (eTLD+1) of the top-level site for this flow, used for cookie partitioning.
    pub top_site: Option<String>,

    
    pub client_protocol: Option<String>,

    
    pub upstream_protocol: Option<String>,

    
    pub behavioral_noise: BehavioralNoiseMetadata,

    pub original_csp_headers: Option<Vec<(HeaderName, Vec<String>)>>,
}

#[derive(Debug, Default)]
pub struct BehavioralNoiseMetadata {
    
    pub enabled: bool,

    pub plan: Option<BehavioralNoisePlan>,

    pub engine_tag: Option<String>,

    pub markers: Vec<String>,
}
