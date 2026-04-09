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

use serde_json::Value;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

use crate::config::{TelemetryConfig, TelemetryMode};

const TELEMETRY_BUFFER_CAP: usize = 300;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event: String,
    pub flow_id: Uuid,
    pub payload: Value,
}

static TELEMETRY_BUFFER: OnceLock<Mutex<Vec<TelemetryEvent>>> = OnceLock::new();

pub fn snapshot() -> Vec<TelemetryEvent> {
    TELEMETRY_BUFFER
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .map(|events| events.clone())
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct TelemetrySink {
    mode: TelemetryMode,
}

impl TelemetrySink {
    pub fn new(cfg: TelemetryConfig) -> Self {
        Self { mode: cfg.mode }
    }

    pub fn emit(&self, event: &str, flow_id: Uuid, payload: Value) {
        let event_name = event.to_string();
        let payload_for_log = payload.clone();

        match self.mode {
            TelemetryMode::Stdout => {
                tracing::info!(%flow_id, event, payload = %payload_for_log);
            }
            TelemetryMode::Json => {
                let data = serde_json::json!({
                    "event": event_name,
                    "flow_id": flow_id,
                    "payload": payload_for_log,
                });
                println!("{}", data);
            }
        }

        if let Ok(mut guard) = TELEMETRY_BUFFER.get_or_init(|| Mutex::new(Vec::new())).lock() {
            guard.push(TelemetryEvent {
                event: event.to_string(),
                flow_id,
                payload: payload_for_log,
            });
            if guard.len() > TELEMETRY_BUFFER_CAP {
                let overflow = guard.len() - TELEMETRY_BUFFER_CAP;
                guard.drain(0..overflow);
            }
        }
    }
}