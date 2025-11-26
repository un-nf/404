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

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use tokio::net::TcpListener;

use crate::{
    config::{Http3Config, ListenerConfig, ProxyProtocol},
    proxy::stages::StagePipeline,
    telemetry::TelemetrySink,
    tls::cert::TlsProvider,
};

use super::connection::handle_connection;

/// ProxyServer manages the TCP listener and spawns per-connection handler tasks.
///
/// - Owns the listening socket (bound to configured address:port)
/// - Accepts incoming connections in a loop
/// - Spawns a tokio task for each connection (concurrent handling)
/// - Shares Arc-wrapped resources (TlsProvider, StagePipeline, TelemetrySink) across tasks
///
/// 1. Created in main.rs with configuration and shared resources
/// 2. run() is called, which binds the listener and enters accept loop
/// 3. Loop runs forever (until Ctrl+C or system shutdown)
/// 4. Each connection is handled independently in a spawned task
///
///
/// **Concurrency:**
/// Tokio's task scheduler handles concurrency. No explicit thread pools or async
/// executors needed; tokio::spawn is sufficient for our workload (I/O-bound, not CPU-bound).
pub struct ProxyServer {
    listener_cfg: ListenerConfig,
    http3_cfg: Http3Config,
    tls: Arc<TlsProvider>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
}

impl ProxyServer {
    /// Creates a new ProxyServer with the given configuration and shared resources.
    ///
    /// **Cloning Semantics:**
    /// - Arc<TlsProvider>: Cheap pointer copy, shares the CA and cert cache
    /// - StagePipeline: Clones the Vec of stage trait objects (Arc'd internally, so cheap)
    /// - TelemetrySink: Clones the logger handle (cheap)
    pub fn new(
        listener_cfg: ListenerConfig,
        http3_cfg: Http3Config,
        tls: Arc<TlsProvider>,
        stages: StagePipeline,
        telemetry: TelemetrySink,
    ) -> Self {
        Self {
            listener_cfg,
            http3_cfg,
            tls,
            stages,
            telemetry,
        }
    }

    /// Starts the server and runs the accept loop until the process is terminated.
    ///
    /// **Protocol Routing:**
    /// Currently both ProxyProtocol::Tls and ProxyProtocol::Plain route to the same
    /// run_listener() implementation. In the future, Plain would skip TLS handshake
    /// and parse HTTP directly from the TCP stream (for testing or plaintext upstream).
    pub async fn run(self) -> Result<()> {
        match self.listener_cfg.proxy_protocol {
            ProxyProtocol::Tls => self.run_listener().await,
            ProxyProtocol::Plain => self.run_listener().await,
        }
    }

    /// Main accept loop: binds the listener, accepts connections, spawns handler tasks.
    ///
    /// **Async Accept Loop:**
    /// ```ignore
    /// loop {
    ///     1. listener.accept() awaits next connection (yields to tokio runtime)
    ///     2. Clone shared resources (Arc clones are cheap pointer copies)
    ///     3. Spawn a task to handle the connection (doesn't block the loop)
    ///     4. Continue accepting (handles multiple connections concurrently)
    /// }
    /// ```
    ///
    /// **Task Spawning:**
    /// tokio::spawn creates a new task on the tokio runtime's thread pool. The task runs
    /// independently (can outlive this function call) and communicates results via channels
    /// or logs (no return value captured here).
    ///
    /// **Error Handling:**
    /// - Bind errors (address already in use, permission denied): propagate to caller (fatal)
    /// - Accept errors (rare, indicates broken socket): propagate to caller (fatal)
    /// - Handler errors (TLS failures, protocol errors): logged in task, doesn't stop server
    ///
    /// **Graceful Shutdown:**
    /// Currently not implemented. When Ctrl+C is pressed, the process terminates immediately.
    /// Future: tokio::signal::ctrl_c() to gracefully finish in-flight connections.
    ///
    /// **Resource Cloning:**
    /// - Arc::clone on TlsProvider: cheap (atomic ref count increment)
    /// - StagePipeline::clone: clones Vec<Arc<dyn FlowStage>>, each Arc is cheap
    /// - TelemetrySink::clone: clones the logger handle
    async fn run_listener(self) -> Result<()> {
        // Parse bind address string (e.g., "127.0.0.1") and combine with port
        let addr = SocketAddr::new(
            self.listener_cfg.bind_address.parse()?,
            self.listener_cfg.bind_port,
        );

        // Bind the listener (async, waits for OS to allocate socket)
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "STATIC listener online");

        let http3_enabled = self.http3_cfg.enabled;

        loop {
            // Accept next client TCP connection (async, yields until client connects)
            let (socket, peer) = listener.accept().await?;

            // Clone shared resources for the spawned task
            // (Arc clones are cheap: just atomic ref count increment)
            let tls = self.tls.clone();
            let stages = self.stages.clone();
            let telemetry = self.telemetry.clone();

            tracing::debug!(%peer, "accepted client");

            // Spawn a task to handle this connection independently
            // (doesn't block the accept loop, allows concurrent connections)
            tokio::spawn(async move {
                // handle_connection does TLS handshake, pipeline execution, data proxy
                if let Err(err) =
                    handle_connection(socket, peer, tls, stages, telemetry, http3_enabled).await
                {
                    // Log errors but don't propagate (one client error shouldn't kill the server)
                    tracing::warn!(%peer, "client session ended with error: {err:?}");
                }
                // Task exits, socket closes (Drop impl on TcpStream)
            });
        }
    }
}
