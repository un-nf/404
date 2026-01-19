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

use std::sync::Arc;

#[derive(Clone)]
pub struct ScriptBundle {
    pub boot: Arc<str>,
    pub shim: Arc<str>,
    pub config_layer: Arc<str>,
    pub spoofing: Arc<str>,
    pub behavioral_noise: Arc<str>,
}

impl ScriptBundle {
    pub fn load() -> Self {
        Self {
            boot: Arc::from(include_str!("../assets/js/0bootstrap_v4.js")),
            shim: Arc::from(include_str!("../assets/js/1globals_shim_v4.js")),
            config_layer: Arc::from(include_str!("../assets/js/config_layer_v3.js")),
            spoofing: Arc::from(include_str!("../assets/js/2fingerprint_spoof_v4.js")),
            behavioral_noise: Arc::from(include_str!("../assets/js/behavioral_noise_v1.js")),
        }
    }
}

