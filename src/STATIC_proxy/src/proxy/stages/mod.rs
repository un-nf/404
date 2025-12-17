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

/// Flow stages replicate the mitmproxy addon chain that lives under `src/proxy/AOs/` in the
/// legacy tree. Each stage implements [`FlowStage`] and the `StagePipeline` drives them in
/// the same deterministic order so HTTP request/response mutations stay identical between
/// the Python prototype and `static_proxy/src/proxy/stages/`.

mod alt_svc;
mod behavior;
mod csp;
mod cookie;
mod header_profile;
mod js;

pub use alt_svc::AltSvcStage;
pub use behavior::BehavioralNoiseStage;
pub use csp::CspStage;
pub use cookie::CookieIsolationStage;
pub use header_profile::HeaderProfileStage;
pub use js::JsInjectionStage;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::{config::PipelineConfig, proxy::flow::Flow, telemetry::TelemetrySink};

#[derive(Clone)]
/// Represents the ordered pipeline of addon stages run for every flow.
pub struct StagePipeline {
    inner: Arc<PipelineInner>,
}

struct PipelineInner {
    stages: Vec<Arc<dyn FlowStage>>,
}

impl StagePipeline {
    /// Builds the pipeline with deterministic ordering so request mutations always happen before
    /// CSP/JS stages and response sanitizers run after script injection.
    pub fn build(cfg: &PipelineConfig, _telemetry: TelemetrySink) -> Result<Self> {
        let mut stages: Vec<Arc<dyn FlowStage>> = Vec::new();

        let psl = Arc::new(publicsuffix::List::new());
        stages.push(Arc::new(CookieIsolationStage::new(psl)));

        stages.push(Arc::new(HeaderProfileStage::new(
            cfg.profiles_path.clone(),
            cfg.default_profile.clone(),
        )?));
        stages.push(Arc::new(BehavioralNoiseStage::new()));
        stages.push(Arc::new(CspStage::default()));
        stages.push(Arc::new(JsInjectionStage::new(cfg.js_debug)));
        stages.push(Arc::new(AltSvcStage::new(cfg.alt_svc_strategy.clone())));

        Ok(Self {
            inner: Arc::new(PipelineInner { stages }),
        })
    }

    pub async fn process_request(&self, flow: &mut Flow) -> Result<()> {
        for stage in &self.inner.stages {
            stage.on_request(flow).await?;
        }
        Ok(())
    }

    pub async fn process_response_headers(&self, flow: &mut Flow) -> Result<()> {
        for stage in &self.inner.stages {
            stage.on_response_headers(flow).await?;
        }
        Ok(())
    }

    pub async fn process_response_body(&self, flow: &mut Flow) -> Result<()> {
        for stage in &self.inner.stages {
            stage.on_response_body(flow).await?;
        }
        Ok(())
    }

    pub async fn finalize_response(&self, flow: &mut Flow) -> Result<()> {
        for stage in &self.inner.stages {
            stage.on_response_finalized(flow).await?;
        }
        Ok(())
    }
}

#[async_trait]

pub trait FlowStage: Send + Sync {
    async fn on_request(&self, _flow: &mut Flow) -> Result<()> {
        
        Ok(())
    }

    async fn on_response_headers(&self, _flow: &mut Flow) -> Result<()> {
        Ok(())
    }

    async fn on_response_body(&self, _flow: &mut Flow) -> Result<()> {
        Ok(())
    }

    async fn on_response_finalized(&self, _flow: &mut Flow) -> Result<()> {
        Ok(())
    }
}
