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

use std::sync::Arc;

use anyhow::Result;

use crate::{
    config::StaticConfig,
    proxy::{stages::StagePipeline, ProxyServer},
    telemetry::TelemetrySink,
    tls::cert::TlsProvider,
};

/// StaticApp that wires together configuration, TLS infrastructure, pipeline stages, and the proxy server.
pub struct StaticApp {
    server: ProxyServer,
}

impl StaticApp {
    /// Constructs a new StaticApp from the given configuration.
    pub async fn new(config: StaticConfig) -> Result<Self> {

        let telemetry = TelemetrySink::new(config.telemetry.clone());

        let tls = Arc::new(TlsProvider::new(config.tls.clone()).await?);

        let pipeline = StagePipeline::build(&config.pipeline, telemetry.clone())?;

        let server = ProxyServer::new(
            config.listener.clone(),
            config.http3.clone(),
            tls,
            pipeline,
            telemetry,
        );

        Ok(Self { server })
    }

    /// Runs the application (binds listener, accepts connections until process exits).
    pub async fn run(self) -> Result<()> {
        self.server.run().await
    }
}
