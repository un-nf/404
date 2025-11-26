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

use anyhow::Result;
use async_trait::async_trait;

use crate::{behavior::BehavioralNoiseEngine, proxy::flow::Flow};

use super::FlowStage;

/// BehavioralNoiseStage coordinates JS + Rust level behavioral spoofing.
///
/// - On the request path we look for telemetry envelopes previously tagged by the
///   JS shim. When we detect one we mutate the serialized body by appending a
///   placeholder block of synthetic events (still structured, not yet populated) and
///   persist markers under `flow.metadata.behavioral_noise` for telemetry.
/// - On the response path we simply mark that the behavioral engine's script must
///   be injected so CSP hashes and JS payloads stay in sync.
#[derive(Clone)]
pub struct BehavioralNoiseStage {
    engine: BehavioralNoiseEngine,
}

impl BehavioralNoiseStage {
    pub fn new() -> Self {
        Self {
            engine: BehavioralNoiseEngine::new(),
        }
    }

    fn annotate_body(&self, flow: &mut Flow) {
        let buffer = &mut flow.request.body;
        if buffer.is_empty() {
            return;
        }
        let plan = match flow.metadata.behavioral_noise.plan.clone() {
            Some(plan) => plan,
            None => return,
        };
        if !self.engine.is_behavioral_envelope(buffer.as_bytes()) {
            return;
        }
        if let Some(updated) = self.engine.append_proxy_noise(buffer.as_bytes(), &plan) {
            buffer.replace(&updated);
            flow.metadata
                .behavioral_noise
                .markers
                .push("proxy_noise_appended".into());
        }
    }
}

#[async_trait]
impl FlowStage for BehavioralNoiseStage {
    async fn on_request(&self, flow: &mut Flow) -> Result<()> {
        if flow.metadata.behavioral_noise.enabled {
            self.annotate_body(flow);
            return Ok(());
        }

        let plan = self.engine.plan_for(flow.id);
        flow.metadata.behavioral_noise.enabled = true;
        flow.metadata.behavioral_noise.engine_tag = Some(self.engine.script_handle().into());
        flow.metadata.behavioral_noise.plan = Some(plan);
        self.annotate_body(flow);
        Ok(())
    }

    async fn on_response_body(&self, flow: &mut Flow) -> Result<()> {
        if flow.metadata.behavioral_noise.enabled {
            flow.metadata
                .behavioral_noise
                .markers
                .push("behavioral_script_injected".into());
        }
        Ok(())
    }
}
