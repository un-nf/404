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

use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderProfile {
    pub name: String,
    pub fingerprint: serde_json::Value,
}

#[derive(Debug, Default)]
/// In-memory store for deterministic header fingerprint profiles.
///
/// Header profiles come from `profiles.json` and drive spoofed headers for each flow.
pub struct ProfileStore {
    profiles: RwLock<HashMap<String, HeaderProfile>>,
}

impl ProfileStore {
    /// Loads profiles from disk and populates the store.
    ///
    /// Accepts both absolute and relative paths and fails if the JSON structure is invalid.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "failed to load header profiles: {}",
                path.as_ref().display()
            )
        })?;
        let json: serde_json::Value =
            serde_json::from_str(&raw).context("profiles.json is not valid JSON")?;

        let mut map = HashMap::new();
        if let Some(obj) = json.get("profiles").and_then(|v| v.as_object()) {
            for (name, value) in obj {
                map.insert(
                    name.clone(),
                    HeaderProfile {
                        name: name.clone(),
                        fingerprint: value.clone(),
                    },
                );
            }
        }

        Ok(Self {
            profiles: RwLock::new(map),
        })
    }

    /// Returns a cloned HeaderProfile by name, if it exists.
    pub fn get(&self, name: &str) -> Option<HeaderProfile> {
        self.profiles.read().get(name).cloned()
    }

    /// Lists all available profile names for telemetry or diagnostics.
    pub fn list(&self) -> Vec<String> {
        self.profiles.read().keys().cloned().collect::<Vec<_>>()
    }
}
