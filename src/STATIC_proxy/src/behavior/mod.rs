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

use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_json::json;
use uuid::Uuid;

const ENGINE_DIRECTORY: &str = "assets/js";
const ENGINE_HANDLE: &str = "behavioral_noise_v1";
const BEHAVIOR_MARKER: &str = "__static_behavioral";

/// JS shim loader + telemetry normalizer helpers.
#[derive(Debug, Clone)]
pub struct BehavioralNoiseEngine {
    script: &'static str,
}

impl BehavioralNoiseEngine {
    /// Creates a new engine reference with the embedded JS payload.
    pub fn new() -> Self {
        Self {
            script: include_str!("../../assets/js/behavioral_noise_v1.js"),
        }
    }

    /// Returns the raw JS shim that must be injected into pages.
    pub fn script(&self) -> &'static str {
        self.script
    }

    /// Returns a stable handle used by other stages for logging / CSP bookkeeping.
    pub fn script_handle(&self) -> &'static str {
        ENGINE_HANDLE
    }

    /// Directory hint (kept for operator-facing metadata).
    pub fn engine_directory(&self) -> &'static str {
        ENGINE_DIRECTORY
    }

    /// Derives a per-flow behavioral plan that both JS and Rust can consult.
    pub fn plan_for(&self, flow_id: Uuid) -> BehavioralNoisePlan {
        let mut seed_bytes = [0u8; 16];
        seed_bytes.copy_from_slice(flow_id.as_bytes());
        let seed = u128::from_be_bytes(seed_bytes) as u64 ^ 0x2002002002002002;
        let mut rng = StdRng::seed_from_u64(seed);

        BehavioralNoisePlan {
            session_key: format!("flow-{}", flow_id),
            cadence_ms: rng.gen_range(250..1200),
            max_buffered_events: rng.gen_range(12..48),
            channel_bias: NoiseChannelBias {
                fetch: rng.gen_range(0.2..0.5),
                beacon: rng.gen_range(0.1..0.4),
                websocket: rng.gen_range(0.1..0.3),
            },
        }
    }

    /// Lightweight heuristic to determine if a body was wrapped by the JS shim.
    pub fn is_behavioral_envelope(&self, body: &[u8]) -> bool {
        if body.is_empty() {
            return false;
        }
        serde_json::from_slice::<serde_json::Value>(body)
            .map(|value| value.get(BEHAVIOR_MARKER).is_some())
            .unwrap_or(false)
    }

    /// Placeholder for future augmentation logic.
    ///
    /// For now we simply append a declarative synthetic event block when the payload
    /// already carries the behavioral marker. The actual event synthesis will be
    /// implemented in collaboration with the JS layer.
    pub fn append_proxy_noise(&self, body: &[u8], plan: &BehavioralNoisePlan) -> Option<Vec<u8>> {
        let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
        if !value.get(BEHAVIOR_MARKER).is_some() {
            return None;
        }

        let noise_block =
            if let Some(existing) = value.get_mut("noise").and_then(|node| node.as_array_mut()) {
                existing
            } else {
                let map = value
                    .as_object_mut()
                    .expect("behavioral envelopes are JSON objects");
                let entry = map
                    .entry(String::from("noise"))
                    .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                entry.as_array_mut().expect("noise array just inserted")
            };

        noise_block.push(json!({
            "source": "proxy",
            "session": plan.session_key,
            "cadence_ms": plan.cadence_ms,
            "channel_bias": {
                "fetch": plan.channel_bias.fetch,
                "beacon": plan.channel_bias.beacon,
                "ws": plan.channel_bias.websocket,
            },
        }));

        serde_json::to_vec(&value).ok()
    }
}

/// Declarative plan shared by JS + proxy to keep noise deterministic per flow.
#[derive(Debug, Clone)]
pub struct BehavioralNoisePlan {
    pub session_key: String,
    pub cadence_ms: u64,
    pub max_buffered_events: u32,
    pub channel_bias: NoiseChannelBias,
}

/// Bias factors describing how often each telemetry channel should carry noise.
#[derive(Debug, Clone, Default)]
pub struct NoiseChannelBias {
    pub fetch: f32,
    pub beacon: f32,
    pub websocket: f32,
}

impl Default for BehavioralNoisePlan {
    fn default() -> Self {
        Self {
            session_key: "flow-bootstrap".into(),
            cadence_ms: 600,
            max_buffered_events: 24,
            channel_bias: NoiseChannelBias::default(),
        }
    }
}

/// Helper exposed so other crates can find the JS asset on disk when needed.
pub fn engine_asset_path() -> &'static str {
    "assets/js/behavioral_noise_v1.js"
}

/// Marker field name shared between JS + proxy when wrapping telemetry payloads.
pub fn marker_field() -> &'static str {
    BEHAVIOR_MARKER
}
