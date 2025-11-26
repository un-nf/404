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

use thiserror::Error;

pub type ProxyResult<T> = Result<T, ProxyError>;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    #[error("Invalid ClientHello: {0}")]
    InvalidClientHello(String),

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
