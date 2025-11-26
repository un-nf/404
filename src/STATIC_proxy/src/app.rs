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
///
/// Encapsulates the "dependency injection" pattern: takes configuration as input,
/// constructs all subsystems (TLS provider, telemetry, stages), and hands them to
/// the ProxyServer. This keeps main.rs simple and makes testing easier (can construct
/// StaticApp with test configs).
///
/// Initialization Order (critical for correctness):
/// 1. Telemetry: Must be first, so subsequent steps can log initialization events
/// 2. TlsProvider: Loads/generates CA, must succeed before server can accept connections
/// 3. StagePipeline: Builds the addon pipeline from config, depends on telemetry for logging
/// 4. ProxyServer: Receives all dependencies, ready to bind listener
pub struct StaticApp {
    /// The proxy server (owns the listener socket and connection handler tasks).
    /// Kept private because external code shouldn't access it directly; use run() instead.
    server: ProxyServer,
}

impl StaticApp {
    /// Constructs a new StaticApp from the given configuration.
    ///
    /// Async Initialization:
    /// This is async because TlsProvider::new is async (filesystem I/O for CA loading).
    /// Even though filesystem I/O is technically blocking, we use tokio::fs to avoid
    /// blocking the runtime during startup (good practice for async apps).
    ///
    /// Arc Wrapping:
    /// TlsProvider is wrapped in Arc because it's shared across all connection tasks.
    /// Arc allows cheap cloning (atomic ref count increment) instead of duplicating
    /// the CA certificate and cache for each connection.
    ///
    /// Errors:
    /// - TlsProvider::new fails → CA generation/loading errors
    /// - StagePipeline::build fails → Invalid stage configuration (unknown stage name, etc.)
    pub async fn new(config: StaticConfig) -> Result<Self> {
        // Initialize telemetry (logging) first so subsequent steps can log
        let telemetry = TelemetrySink::new(config.telemetry.clone());

        // Initialize TLS provider (load/generate CA, prepare cert cache)
        let tls = Arc::new(TlsProvider::new(config.tls.clone()).await?);

        // Build the addon pipeline (CSP, JS injection, header spoofing, etc.)
        let pipeline = StagePipeline::build(&config.pipeline, telemetry.clone())?;

        // Create the proxy server (owns listener, spawns connection tasks)
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
    ///
    /// Blocking Behavior:
    /// This function never returns under normal operation (runs the accept loop forever).
    /// Only returns Err if the listener bind fails or if Ctrl+C is handled gracefully
    /// in the future (not yet implemented).
    ///
    /// Ownership:
    /// Consumes self (takes ownership) because the server needs to own all resources
    /// (TlsProvider, StagePipeline, TelemetrySink) for the lifetime of the process.
    pub async fn run(self) -> Result<()> {
        self.server.run().await
    }
}
