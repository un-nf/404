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

/// Configuration-related modules (settings + fingerprint profiles) exposed by the crate.
pub mod profiles;
pub mod settings;

pub use profiles::{HeaderProfile, ProfileStore};
pub use settings::{
    AltSvcStrategy, Http3Config, ListenerConfig, PipelineConfig, ProxyProtocol, StaticConfig,
    TelemetryConfig, TelemetryMode, TlsConfig,
};
