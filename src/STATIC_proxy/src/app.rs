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

use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Result;
use tokio::sync::watch;

use crate::{
    config::StaticConfig,
    control::{ControlMode, ControlPlane},
    proxy::{stages::StagePipeline, OriginFetcher, ProxyServer, WreqOriginFetcher},
    telemetry::TelemetrySink,
    tls::cert::TlsProvider,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    Proxy,
    ControlOnly,
}

impl RunMode {
    fn control_mode(self) -> ControlMode {
        match self {
            Self::Proxy => ControlMode::Proxy,
            Self::ControlOnly => ControlMode::Control,
        }
    }
}

/// StaticApp that wires together configuration, TLS infrastructure, pipeline stages, and the proxy server.
pub struct StaticApp {
    control: ControlPlane,
    server: Option<ProxyServer>,
}

impl StaticApp {
    /// Constructs a new StaticApp from the given configuration.
    pub async fn new(config: StaticConfig, mode: RunMode) -> Result<Self> {
        let ready = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = match mode {
            RunMode::Proxy => {
                let telemetry = TelemetrySink::new(config.telemetry.clone());
                let tls = Arc::new(TlsProvider::new(config.tls.clone()).await?);
                let pipeline = StagePipeline::build(&config.pipeline, telemetry.clone())?;
                let fetcher: Arc<dyn OriginFetcher> = Arc::new(WreqOriginFetcher::new());

                Some(ProxyServer::new(
                    config.listener.clone(),
                    config.http3.clone(),
                    tls,
                    fetcher,
                    pipeline,
                    telemetry,
                    ready.clone(),
                    shutdown_rx,
                ))
            }
            RunMode::ControlOnly => None,
        };

        let control = ControlPlane::new(config, mode.control_mode(), ready, shutdown_tx);

        Ok(Self { control, server })
    }

    /// Runs the application (binds listener, accepts connections until process exits).
    pub async fn run(self) -> Result<()> {
        let shutdown = self.control.clone();
        let mut control_task = tokio::spawn(self.control.run());

        let Some(server) = self.server else {
            return flatten_task_result(control_task.await);
        };

        let mut server_task = tokio::spawn(server.run());

        let first_result = tokio::select! {
            result = &mut control_task => TaskExit::Control(result),
            result = &mut server_task => TaskExit::Server(result),
        };

        shutdown.request_shutdown();

        match first_result {
            TaskExit::Control(result) => {
                let control_result = flatten_task_result(result);
                let server_result = flatten_task_result(server_task.await);
                control_result.and(server_result)
            }
            TaskExit::Server(result) => {
                let server_result = flatten_task_result(result);
                let control_result = flatten_task_result(control_task.await);
                server_result.and(control_result)
            }
        }
    }
}

enum TaskExit {
    Control(Result<Result<()>, tokio::task::JoinError>),
    Server(Result<Result<()>, tokio::task::JoinError>),
}

fn flatten_task_result(result: Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    match result {
        Ok(inner) => inner,
        Err(err) => Err(err.into()),
    }
}
