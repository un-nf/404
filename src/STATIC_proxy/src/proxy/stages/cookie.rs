/* STATIC Proxy (AGPL-3.0)

Stateless cookie filtering:
- Responses: allow Set-Cookie only if Domain aligns with the current top-site; otherwise rewrite to host-only and, when HTTPS, force Secure + SameSite=Strict. Anything unparsable is dropped. No server-side storage.
- Requests: best-effort parse Cookie header, drop invalid pairs, reserialize. (Domain/path are not present in Cookie header by spec, so we cannot further filter without state.)
*/

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use cookie::{Cookie, SameSite};
use http::header::{HeaderValue, COOKIE, HOST, REFERER, SET_COOKIE};
use publicsuffix::{List, Psl};

use crate::proxy::flow::Flow;

use super::FlowStage;

#[derive(Clone)]
pub struct CookieIsolationStage {
    psl: Arc<List>,
}

impl CookieIsolationStage {
    pub fn new(psl: Arc<List>) -> Self {
        Self { psl }
    }

    fn ensure_top_site(&self, flow: &mut Flow) -> Option<String> {
        if let Some(site) = flow.metadata.top_site.clone() {
            return Some(site);
        }

        let host = extract_host(flow)?;
        let top = self.registrable_domain(&host).unwrap_or_else(|| host.clone());
        flow.metadata.top_site = Some(top.clone());
        Some(top)
    }

    fn registrable_domain(&self, host: &str) -> Option<String> {
        self
            .psl
            .domain(host.as_bytes())
            .and_then(|d| core::str::from_utf8(d.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    fn on_response_headers_inner(&self, flow: &mut Flow) -> Result<()> {
        let Some(req_host) = extract_host(flow) else { return Ok(()); };
        let Some(top_site) = self.ensure_top_site(flow) else { return Ok(()); };
        let Some(mut response) = flow.response.as_mut() else { return Ok(()); };

        let is_https = flow
            .request
            .uri
            .scheme_str()
            .map(|s| s.eq_ignore_ascii_case("https"))
            .unwrap_or(true);

        let set_cookies: Vec<String> = response
            .headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect();

        response.headers.remove(SET_COOKIE);

        for raw in set_cookies {
            let Ok(mut c) = Cookie::parse(raw.as_str()) else { continue };

            // Normalize domain
            let dom_opt = c.domain().map(|d| d.trim_start_matches('.').to_ascii_lowercase());
            let dom_matches_top = dom_opt
                .as_deref()
                .and_then(|d| self.registrable_domain(d))
                .map(|d| d.eq_ignore_ascii_case(&top_site))
                .unwrap_or(true);

            if !dom_matches_top {
                c.set_domain(req_host.as_str());
                c.set_same_site(Some(SameSite::Strict));
                if is_https {
                    c.set_secure(true);
                }
            }

            if c.domain().is_some() {
                // Ensure domain still matches the request host's top site; otherwise drop.
                let dom_ok = c
                    .domain()
                    .and_then(|d| self.registrable_domain(d.trim_start_matches('.')))
                    .map(|d| d.eq_ignore_ascii_case(&top_site))
                    .unwrap_or(false);
                if !dom_ok {
                    continue;
                }
            }

            if is_https {
                c.set_secure(true);
            }
            if c.same_site().is_none() && is_https {
                c.set_same_site(Some(SameSite::Strict));
            }

            // Host-only enforcement if domain missing
            if c.domain().is_none() {
                c.set_domain(req_host.as_str());
            }

            let val = HeaderValue::from_str(&c.to_string()).context("invalid Set-Cookie after filtering")?;
            response.headers.append(SET_COOKIE, val);
        }

        Ok(())
    }

    fn on_request_inner(&self, flow: &mut Flow) -> Result<()> {
        let mut collected = String::new();
        let mut first = true;

        let mut to_remove = Vec::new();

        for (idx, value) in flow.request.headers.get_all(COOKIE).iter().enumerate() {
            let Ok(raw) = value.to_str() else { to_remove.push(idx); continue };
            for parsed in Cookie::split_parse(raw) {
                let Ok(c) = parsed else { continue };
                if !first {
                    collected.push_str("; ");
                }
                first = false;
                collected.push_str(c.name());
                collected.push('=');
                collected.push_str(c.value());
            }
        }

        flow.request.headers.remove(COOKIE);
        if !collected.is_empty() {
            let val = HeaderValue::from_str(&collected).context("invalid Cookie after filtering")?;
            flow.request.headers.insert(COOKIE, val);
        }

        Ok(())
    }
}

#[async_trait]
impl FlowStage for CookieIsolationStage {
    async fn on_request(&self, flow: &mut Flow) -> Result<()> {
        self.on_request_inner(flow)
    }

    async fn on_response_headers(&self, flow: &mut Flow) -> Result<()> {
        self.on_response_headers_inner(flow)
    }
}

fn extract_host(flow: &Flow) -> Option<String> {
    if let Some(host) = flow.request.uri.host().map(|h| h.to_ascii_lowercase()) {
        return Some(host);
    }

    if let Some(host_header) = flow.request.headers.get(HOST).and_then(|h| h.to_str().ok()) {
        return Some(host_header.to_ascii_lowercase());
    }

    referer_host(flow)
}

fn referer_host(flow: &Flow) -> Option<String> {
    flow
        .request
        .headers
        .get(REFERER)
        .and_then(|h| h.to_str().ok())
        .and_then(|r| r.parse::<http::Uri>().ok())
        .and_then(|uri| uri.host().map(|h| h.to_ascii_lowercase()))
}
