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

use bytes::Bytes;

use crate::utils::ProxyResult;

/// Minimal ClientHello representation for JA3 fingerprinting scaffolding.
///
/// The runtime does not yet parse raw TLS handshakes, but keeping these fields
/// in place lets us unit-test JA3 helpers and wire up real parsers later without
/// refactoring downstream consumers.
#[derive(Debug, Clone, Default)]
pub struct ClientHello {
    /// Optional hostname the client advertised via SNI.
    pub sni: Option<String>,
    /// TLS protocol version as advertised in the ClientHello record.
    pub version: u16,
    /// Ordered list of cipher suites proposed by the client.
    pub cipher_suites: Vec<u16>,
    /// Ordered list of extension identifiers found in the ClientHello.
    pub extensions: Vec<u16>,
    /// Elliptic curve IDs (supported groups) used in JA3 position four.
    pub elliptic_curves: Vec<u16>,
    /// EC point format codes used in JA3 position five.
    pub ec_point_formats: Vec<u8>,
}

impl ClientHello {
    pub fn parse(_bytes: &Bytes) -> ProxyResult<Self> {
        Err(crate::utils::error::ProxyError::InvalidClientHello(
            "parser not implemented".into(),
        ))
    }
}
