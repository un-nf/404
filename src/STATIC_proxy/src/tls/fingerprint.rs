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

use md5::{Digest, Md5};

use crate::utils::ProxyResult;

use super::handshake::ClientHello;

/// JA3 hash builder (version,ciphers,extensions,curves,formats).
///
/// The current ClientHello scaffolding is populated only in tests, but the helper now
/// mirrors the real JA3 component ordering so we can drop in parsed data later without
/// changing downstream logic.
pub fn calculate_ja3(hello: &ClientHello) -> ProxyResult<String> {
    let components = format!(
        "{},{},{},{},{}",
        hello.version,
        join_u16(&hello.cipher_suites),
        join_u16(&hello.extensions),
        join_u16(&hello.elliptic_curves),
        join_u8(&hello.ec_point_formats),
    );
    let mut hasher = Md5::new();
    hasher.update(components.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

    fn join_u8(values: &[u8]) -> String {
        values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
    }

pub fn validate_profile(hello: &ClientHello, expected: &str) -> ProxyResult<bool> {
    Ok(calculate_ja3(hello)? == expected)
}
