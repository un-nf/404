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

use std::fs;

use http::header::{ACCEPT_LANGUAGE, SEC_CH_UA, SEC_FETCH_SITE, USER_AGENT};
use http::{HeaderValue, Method, Uri, Version};
use serde_json::json;
use static_proxy::proxy::flow::{BodyBuffer, Flow, RequestParts};
use static_proxy::proxy::stages::HeaderProfileStage;
use tempfile::tempdir;

fn build_flow() -> Flow {
    let mut headers = http::HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("automation"));
    headers.insert(SEC_CH_UA, HeaderValue::from_static("\"Not A;Brand\""));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US"));

    Flow::new(RequestParts {
        method: Method::GET,
        uri: Uri::from_static("https://example.com/"),
        version: Version::HTTP_11,
        headers,
        body: BodyBuffer::default(),
    })
}

#[tokio::test]
async fn header_profile_stage_spoofs_headers_and_metadata() {
    let dir = tempdir().expect("tempdir");
    let profile = json!({
        "fingerprint": {"name": "Firefox Windows"},
        "remove": ["Sec-CH-UA"],
        "replace": [["User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]],
        "set": [["Sec-Fetch-Site", "same-origin"]],
        "append": [["Accept-Language", "en-US,en;q=0.9"]],
        "tls": {
            "schema_version": 2,
            "versions": {"min": "tls12", "max": "tls13"},
            "cipher_catalog": {"tls13": [], "tls12": []},
            "hello_variants": []
        }
    });
    let profile_path = dir.path().join("firefox-windows.json");
    fs::write(&profile_path, serde_json::to_string_pretty(&profile)).expect("write profile");

    let stage = HeaderProfileStage::new(dir.path().to_path_buf(), "firefox-windows".into())
        .expect("stage initializes");
    let mut flow = build_flow();

    stage
        .on_request(&mut flow)
        .await
        .expect("stage rewrites headers");

    // Metadata mirrors selected profile
    assert_eq!(flow.metadata.profile_name.as_deref(), Some("Firefox Windows"));
    assert_eq!(flow.metadata.browser_profile.as_deref(), Some("firefox-windows"));
    assert_eq!(
        flow.metadata.user_agent.as_deref(),
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    );
    assert_eq!(
        flow.metadata
            .fingerprint_config
            .get("fingerprint")
            .and_then(|fp| fp.get("name"))
            .and_then(|name| name.as_str()),
        Some("Firefox Windows")
    );

    // Headers rewritten per profile rules
    assert!(flow.request.headers.get(SEC_CH_UA).is_none());
    assert_eq!(
        flow.request
            .headers
            .get(USER_AGENT)
            .and_then(|value| value.to_str().ok()),
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    );
    assert_eq!(
        flow.request
            .headers
            .get(SEC_FETCH_SITE)
            .and_then(|value| value.to_str().ok()),
        Some("same-origin")
    );

    let languages: Vec<_> = flow
        .request
        .headers
        .get_all(ACCEPT_LANGUAGE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    assert_eq!(languages, vec!["en-US", "en-US,en;q=0.9"]);
}
