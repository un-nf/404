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
use std::sync::OnceLock;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::{TelemetryConfig, TelemetryMode};

#[derive(Clone, Debug)]
pub struct TelemetryEvent {
    pub event: String,
    pub flow_id: Uuid,
    pub payload: Value,
}

static TELEMETRY_TX: OnceLock<broadcast::Sender<TelemetryEvent>> = OnceLock::new();

pub fn register_global_telemetry_sender(tx: broadcast::Sender<TelemetryEvent>) {
    let _ = TELEMETRY_TX.set(tx);
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

        if let Some(tx) = TELEMETRY_TX.get() {
            let _ = tx.send(TelemetryEvent {
                event: event_name,
                flow_id,
                payload,
            });
        }
    }
}