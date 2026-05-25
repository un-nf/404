use std::{
    fs,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{net::TcpListener, sync::watch};

use crate::{
    config::{managed_ca_cert_path, StaticConfig},
    ebpf,
    proxy::stages::{ProfileCatalogEntry, ProfileStore},
    telemetry,
    tls::{cert::{current_ca_certificate_pem, initialize_ca_material}, profiles::validate_profile_coherence},
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
    control_token: Option<String>,
    mode: ControlMode,
    profile_store: ProfileStore,
    ready: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Clone)]
struct ControlState {
    config: StaticConfig,
    control_token: Option<String>,
    mode: ControlMode,
    profile_store: ProfileStore,
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
    cert_pem: String,
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

#[derive(Serialize)]
struct ProfileCatalogResponse {
    active_profile: Option<ProfileCatalogEntry>,
    profiles: Vec<ProfileCatalogEntry>,
}

#[derive(Serialize)]
struct ActiveProfileResponse {
    active_profile: Option<ProfileCatalogEntry>,
}

#[derive(Deserialize)]
struct ProfileSelectionRequest {
    profile: String,
}

#[derive(Serialize)]
struct ProfileSelectionResponse {
    active_profile: ProfileCatalogEntry,
}

impl ControlPlane {
    pub fn new(
        config: StaticConfig,
        mode: ControlMode,
        ready: Arc<AtomicBool>,
        shutdown_tx: watch::Sender<bool>,
        profile_store: ProfileStore,
    ) -> Self {
        let control_token = load_control_token(&config)
            .expect("STATIC control token path must be readable when configured");
        Self {
            config,
            control_token,
            mode,
            profile_store,
            ready,
            shutdown_tx,
        }
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn run(self) -> Result<()> {
        let bind_ip = self
            .config
            .control
            .bind_address
            .parse::<IpAddr>()
            .map_err(|e| anyhow::anyhow!("invalid control.bind_address '{}': {e}", self.config.control.bind_address))?;
        let addr = SocketAddr::from((bind_ip, control_port(self.config.listener.bind_port)));
        let listener = TcpListener::bind(addr).await?;
        if self.mode == ControlMode::Control {
            self.ready.store(true, Ordering::SeqCst);
        }
        tracing::info!(%addr, "STATIC control plane online");

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let ready = Arc::clone(&self.ready);
        let state = ControlState {
            config: self.config,
            control_token: self.control_token,
            mode: self.mode,
            profile_store: self.profile_store,
            ready,
            shutdown_tx: self.shutdown_tx,
        };

        let app = Router::new()
            .route("/status", get(get_status))
            .route("/ca/status", get(get_ca_status))
            .route("/ca/init", post(post_ca_init))
            .route("/stop", post(post_stop))
            .route("/telemetry/snapshot", get(get_telemetry_snapshot))
            .route("/profiles/catalog", get(get_profile_catalog))
            .route("/profiles/active", get(get_active_profile))
            .route("/profiles/select", post(post_profile_select))
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

fn load_control_token(config: &StaticConfig) -> Result<Option<String>> {
    let Some(path) = config.control.token_path.as_ref() else {
        return Ok(None);
    };

    let token = fs::read_to_string(path)?;
    let token = token.trim().to_string();
    if token.is_empty() {
        Ok(None)
    } else {
        Ok(Some(token))
    }
}

fn require_control_auth(headers: &HeaderMap, state: &ControlState) -> Result<(), (StatusCode, String)> {
    let Some(expected_token) = state.control_token.as_deref() else {
        return Ok(());
    };

    let presented = headers
        .get("X-404-Control-Token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| (StatusCode::FORBIDDEN, "missing control token".to_string()))?;

    if presented == expected_token {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "invalid control token".to_string()))
    }
}

async fn get_status(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    Ok(Json(StatusResponse {
        mode: state.mode,
        ready: state.ready.load(Ordering::SeqCst),
    }))
}

async fn get_ca_status(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Result<Json<CaStatusResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    let cert_path = managed_ca_cert_path();
    let cert_pem = if cert_path.exists() {
        current_ca_certificate_pem(&state.config.tls)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read CA certificate: {e}")))?
    } else {
        String::new()
    };
    Ok(Json(CaStatusResponse {
        cert_path: cert_path.to_string_lossy().to_string(),
        exists: cert_path.exists(),
        cert_pem,
    }))
}

async fn post_ca_init(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Result<Json<CaStatusResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    initialize_ca_material(&state.config.tls)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to init CA: {e}")))?;

    let cert_path = managed_ca_cert_path();
    let cert_pem = current_ca_certificate_pem(&state.config.tls)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read CA certificate: {e}")))?;
    Ok(Json(CaStatusResponse {
        cert_path: cert_path.to_string_lossy().to_string(),
        exists: cert_path.exists(),
        cert_pem,
    }))
}

async fn post_stop(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Result<Json<StopResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    let _ = state.shutdown_tx.send(true);
    Ok(Json(StopResponse { stopping: true }))
}

async fn get_telemetry_snapshot(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Result<Json<TelemetrySnapshotResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    Ok(Json(TelemetrySnapshotResponse {
        events: telemetry::snapshot(),
    }))
}

async fn get_profile_catalog(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Result<Json<ProfileCatalogResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    Ok(Json(ProfileCatalogResponse {
        active_profile: state.profile_store.active_profile(),
        profiles: state.profile_store.catalog(),
    }))
}

async fn get_active_profile(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Result<Json<ActiveProfileResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    Ok(Json(ActiveProfileResponse {
        active_profile: state.profile_store.active_profile(),
    }))
}

async fn post_profile_select(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<ProfileSelectionRequest>,
) -> Result<Json<ProfileSelectionResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    let active_profile = state
        .profile_store
        .select_profile(&request.profile)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ebpf::sync_profile_store(&state.profile_store);

    Ok(Json(ProfileSelectionResponse { active_profile }))
}

async fn post_profile_validate(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<ProfileValidationRequest>,
) -> Result<Json<ProfileValidationResponse>, (StatusCode, String)> {
    require_control_auth(&headers, &state)?;
    Ok(Json(ProfileValidationResponse {
        warnings: validate_profile_coherence(&request.profile),
    }))
}