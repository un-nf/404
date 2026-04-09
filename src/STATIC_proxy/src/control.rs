use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{net::TcpListener, sync::watch};

use crate::{
    config::{managed_ca_cert_path, StaticConfig},
    telemetry,
    tls::{cert::initialize_ca_material, profiles::validate_profile_coherence},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ControlMode {
    Proxy,
    Control,
}

#[derive(Clone)]
pub struct ControlPlane {
    config: StaticConfig,
    mode: ControlMode,
    ready: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Clone)]
struct ControlState {
    config: StaticConfig,
    mode: ControlMode,
    ready: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Serialize)]
struct StatusResponse {
    mode: ControlMode,
    ready: bool,
}

#[derive(Serialize)]
struct CaStatusResponse {
    cert_path: String,
    exists: bool,
}

#[derive(Serialize)]
struct StopResponse {
    stopping: bool,
}

#[derive(Serialize)]
struct TelemetrySnapshotResponse {
    events: Vec<telemetry::TelemetryEvent>,
}

#[derive(Deserialize)]
struct ProfileValidationRequest {
    profile: Value,
}

#[derive(Serialize)]
struct ProfileValidationResponse {
    warnings: Vec<String>,
}

impl ControlPlane {
    pub fn new(config: StaticConfig, mode: ControlMode, ready: Arc<AtomicBool>, shutdown_tx: watch::Sender<bool>) -> Self {
        Self {
            config,
            mode,
            ready,
            shutdown_tx,
        }
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn run(self) -> Result<()> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, control_port(self.config.listener.bind_port)));
        let listener = TcpListener::bind(addr).await?;
        if self.mode == ControlMode::Control {
            self.ready.store(true, Ordering::SeqCst);
        }
        tracing::info!(%addr, "STATIC control plane online");

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let ready = Arc::clone(&self.ready);
        let state = ControlState {
            config: self.config,
            mode: self.mode,
            ready,
            shutdown_tx: self.shutdown_tx,
        };

        let app = Router::new()
            .route("/status", get(get_status))
            .route("/ca/status", get(get_ca_status))
            .route("/ca/init", post(post_ca_init))
            .route("/stop", post(post_stop))
            .route("/telemetry/snapshot", get(get_telemetry_snapshot))
            .route("/profiles/validate", post(post_profile_validate))
            .with_state(state);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                while shutdown_rx.changed().await.is_ok() {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            })
            .await?;

        self.ready.store(false, Ordering::SeqCst);

        Ok(())
    }
}

pub fn control_port(bind_port: u16) -> u16 {
    bind_port.saturating_add(2)
}

async fn get_status(State(state): State<ControlState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        mode: state.mode,
        ready: state.ready.load(Ordering::SeqCst),
    })
}

async fn get_ca_status() -> Json<CaStatusResponse> {
    let cert_path = managed_ca_cert_path();
    Json(CaStatusResponse {
        cert_path: cert_path.to_string_lossy().to_string(),
        exists: cert_path.exists(),
    })
}

async fn post_ca_init(
    State(state): State<ControlState>,
) -> Result<Json<CaStatusResponse>, (StatusCode, String)> {
    initialize_ca_material(&state.config.tls)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to init CA: {e}")))?;

    let cert_path = managed_ca_cert_path();
    Ok(Json(CaStatusResponse {
        cert_path: cert_path.to_string_lossy().to_string(),
        exists: cert_path.exists(),
    }))
}

async fn post_stop(State(state): State<ControlState>) -> Json<StopResponse> {
    let _ = state.shutdown_tx.send(true);
    Json(StopResponse { stopping: true })
}

async fn get_telemetry_snapshot() -> Json<TelemetrySnapshotResponse> {
    Json(TelemetrySnapshotResponse {
        events: telemetry::snapshot(),
    })
}

async fn post_profile_validate(
    Json(request): Json<ProfileValidationRequest>,
) -> Json<ProfileValidationResponse> {
    Json(ProfileValidationResponse {
        warnings: validate_profile_coherence(&request.profile),
    })
}