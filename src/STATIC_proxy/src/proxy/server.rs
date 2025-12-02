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
pub struct ProxyServer {
    listener_cfg: ListenerConfig,
    http3_cfg: Http3Config,
    tls: Arc<TlsProvider>,
    stages: StagePipeline,
    telemetry: TelemetrySink,
}

impl ProxyServer {
    /// Creates a new ProxyServer with the given configuration and shared resources.
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
    pub async fn run(self) -> Result<()> {
        match self.listener_cfg.proxy_protocol {
            ProxyProtocol::Tls => self.run_listener().await,
            ProxyProtocol::Plain => self.run_listener().await,
        }
    }

    /// Main accept loop: binds the listener, accepts connections, spawns handler tasks.
    async fn run_listener(self) -> Result<()> {

        let addr = SocketAddr::new(
            self.listener_cfg.bind_address.parse()?,
            self.listener_cfg.bind_port,
        );

        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "STATIC listener online");

        let http3_enabled = self.http3_cfg.enabled;

        loop {

            let (socket, peer) = listener.accept().await?;
            let tls = self.tls.clone();
            let stages = self.stages.clone();
            let telemetry = self.telemetry.clone();

            tracing::debug!(%peer, "accepted client");

            tokio::spawn(async move {

                if let Err(err) =
                    handle_connection(socket, peer, tls, stages, telemetry, http3_enabled).await
                {
                    
                    tracing::warn!(%peer, "client session ended with error: {err:?}");
                }
                
            });
        }
    }
}
