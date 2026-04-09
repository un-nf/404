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

use std::sync::OnceLock;

use anyhow::{anyhow, Result};

pub mod app;
pub mod assets;
pub mod behavior;
pub mod config;
pub mod control;
pub mod keystore;
pub mod proxy;
pub mod telemetry;
pub mod tls;
pub mod utils;

static RUSTLS_PROVIDER_INIT: OnceLock<Result<(), String>> = OnceLock::new();

pub fn ensure_rustls_crypto_provider() -> Result<()> {
	let result = RUSTLS_PROVIDER_INIT.get_or_init(|| {
		rustls::crypto::aws_lc_rs::default_provider()
			.install_default()
			.map_err(|_| "failed to install aws-lc-rs as the process-level rustls CryptoProvider".to_string())
	});

	result
		.as_ref()
		.map(|_| ())
		.map_err(|message| anyhow!(message.clone()))
}
