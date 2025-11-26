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

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use http::header::{self, HeaderValue};

use crate::{config::AltSvcStrategy, proxy::flow::Flow};

use super::FlowStage;

/// AltSvcStage normalizes or removes `Alt-Svc` headers before they leave the proxy.
/// Mirrors the legacy mitmproxy addon: downgrade HTTP/3 advertisements to h2, enforce
/// safe ports, or strip the header entirely depending on `AltSvcStrategy`.
#[derive(Debug, Clone)]
pub struct AltSvcStage {
    strategy: AltSvcStrategy,
}

impl AltSvcStage {
    const SAFE_PORTS: &'static [(&'static str, &'static str)] = &[
        ("443", "443"),
        ("80", "80"),
        ("8080", "443"),
        ("8443", "443"),
        ("3128", "443"),
    ];

    /// Constructs a new AltSvcStage using the supplied strategy.
    pub fn new(strategy: AltSvcStrategy) -> Self {
        Self { strategy }
    }

    fn normalize_port(authority: &str) -> String {
        if authority.is_empty() {
            return authority.to_string();
        }

        if let Some(stripped) = authority.strip_prefix(':') {
            if let Some(mapped) = Self::map_port(stripped) {
                return format!(":{}", mapped);
            }
            return authority.to_string();
        }

        if let Some((host, port)) = authority.rsplit_once(':') {
            if let Some(mapped) = Self::map_port(port) {
                return format!("{}:{}", host, mapped);
            }
        }

        authority.to_string()
    }

    fn map_port(port: &str) -> Option<&'static str> {
        Self::SAFE_PORTS
            .iter()
            .find_map(|(from, to)| if *from == port { Some(*to) } else { None })
    }

    fn process_header_value(&self, value: &str) -> Result<Option<String>> {
        if value.trim().is_empty() || value.eq_ignore_ascii_case("clear") {
            return Ok(None);
        }

        match self.strategy {
            AltSvcStrategy::Remove => return Ok(None),
            _ => {}
        }

        let mut services = self.parse_services(value);
        if services.is_empty() {
            return Ok(None);
        }

        match self.strategy {
            AltSvcStrategy::Normalize => {
                self.normalize_services(&mut services);
            }
            AltSvcStrategy::Redirect => {
                self.redirect_services(&mut services);
            }
            AltSvcStrategy::Remove => unreachable!(),
        }

        services.retain(|svc| svc.protocol.is_some());
        if services.is_empty() {
            return Ok(None);
        }

        Ok(Some(self.reconstruct_services(&services)))
    }

    fn parse_services(&self, value: &str) -> Vec<AltSvcService> {
        value
            .split(',')
            .filter_map(|raw| self.parse_service(raw.trim()))
            .collect()
    }

    fn parse_service(&self, entry: &str) -> Option<AltSvcService> {
        if entry.is_empty() {
            return None;
        }

        let mut parts = entry.split(';');
        let primary = parts.next()?.trim();
        let (protocol, authority) = primary.split_once('=')?;

        let protocol = protocol.trim().to_string();
        let raw_authority = authority.trim().trim_matches('"');
        let authority = if raw_authority.is_empty() {
            None
        } else {
            Some(raw_authority.to_string())
        };

        let mut service = AltSvcService {
            protocol: Some(protocol),
            authority,
            params: Vec::new(),
        };

        for param in parts {
            if let Some((key, value)) = param.split_once('=') {
                service.params.push((key.trim().to_string(), value.trim().to_string()));
            }
        }

        Some(service)
    }

    fn normalize_services(&self, services: &mut [AltSvcService]) {
        for service in services.iter_mut() {
            if let Some(authority) = service.authority.as_ref() {
                let normalized = Self::normalize_port(authority);
                service.authority = Some(normalized);
            }

            if let Some(protocol) = service.protocol.as_mut() {
                if Self::is_risky_protocol(protocol) {
                    *protocol = "h2".to_string();
                    if service.authority.as_deref().unwrap_or("").is_empty() {
                        service.authority = Some(":443".to_string());
                    }
                }
            }
        }
    }

    fn redirect_services(&self, services: &mut [AltSvcService]) {
        for service in services.iter_mut() {
            if let Some(authority) = service.authority.as_ref() {
                let rewritten = if authority.starts_with(':') {
                    ":443".to_string()
                } else if let Some((host, _)) = authority.rsplit_once(':') {
                    format!("{}:443", host)
                } else {
                    format!("{}:443", authority)
                };
                service.authority = Some(rewritten);
            } else {
                service.authority = Some(":443".to_string());
            }
        }
    }

    fn reconstruct_services(&self, services: &[AltSvcService]) -> String {
        services
            .iter()
            .filter_map(|svc| {
                let protocol = svc.protocol.as_ref()?;
                let authority = svc.authority.as_ref()?;
                let mut segments = vec![format!("{}=\"{}\"", protocol, authority)];
                for (key, value) in &svc.params {
                    segments.push(format!("{}={}", key, value));
                }
                Some(segments.join("; "))
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn is_risky_protocol(protocol: &str) -> bool {
        let lowered = protocol.to_ascii_lowercase();
        lowered.starts_with("h3") || lowered == "quic"
    }
}

#[derive(Debug, Clone)]
struct AltSvcService {
    protocol: Option<String>,
    authority: Option<String>,
    params: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_downgrades_h3_to_h2() {
        let stage = AltSvcStage::new(AltSvcStrategy::Normalize);
        let value = r#"h3=":443"; ma=86400, h3-29="alt.example:8080"; ma=60"#;
        let result = stage.process_header_value(value).unwrap().unwrap();
        assert_eq!(result, "h2=\":443\"; ma=86400, h2=\"alt.example:443\"; ma=60");
    }

    #[test]
    fn remove_strategy_drops_header() {
        let stage = AltSvcStage::new(AltSvcStrategy::Remove);
        let value = "h3=\":443\"";
        assert!(stage.process_header_value(value).unwrap().is_none());
    }
}

#[async_trait]
impl FlowStage for AltSvcStage {
    /// Normalizes Alt-Svc headers and downgrades HTTP/3 advertisements to h2.
    async fn on_response_headers(&self, flow: &mut Flow) -> Result<()> {
        let response = match flow.response.as_mut() {
            Some(resp) => resp,
            None => return Ok(()),
        };

        let values: Vec<String> = response
            .headers
            .get_all(header::ALT_SVC)
            .iter()
            .filter_map(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .collect();

        if values.is_empty() {
            return Ok(());
        }

        response.headers.remove(header::ALT_SVC);
        let mut applied = Vec::new();
        for value in values {
            match self.process_header_value(&value) {
                Ok(Some(new_value)) => {
                    if new_value.is_empty() {
                        continue;
                    }
                    let header_value = HeaderValue::from_str(&new_value)
                        .with_context(|| "invalid Alt-Svc header produced by AltSvcStage")?;
                    response.headers.append(header::ALT_SVC, header_value);
                    applied.push(format!("{} -> {}", value, new_value));
                }
                Ok(None) => {
                    applied.push(format!("{} -> <removed>", value));
                }
                Err(err) => {
                    bail!("Alt-Svc processing failed: {}", err);
                }
            }
        }

        if !applied.is_empty() {
            flow.metadata
                .alt_svc_mutations
                .push(format!("{:?}: {}", self.strategy, applied.join(" | ")));
        }

        Ok(())
    }
}
