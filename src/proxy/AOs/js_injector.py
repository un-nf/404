""" JavaScript Injector Addon for mitmproxy

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
"""
# JavaScript injector addon for browser fingerprint protection


import json
import os
import hashlib
import base64
from pathlib import Path
from typing import Optional
from mitmproxy import ctx, http

class JSInjector:

    def __init__(self):
        # Check for debug mode environment variable
        self.debug = os.getenv('FINGERPRINT_DEBUG', '0').lower() in ('1', 'true', 'yes')
        self.enabled = False
        self.layers = {}
        self.layer_hashes = {}  # Store SHA-256 hashes of each layer
        self.inject_count = 0

        if self.debug:
            ctx.log.info("[JSInjector] Debug mode ENABLED via FINGERPRINT_DEBUG environment variable")

    def _compute_script_hash(self, script_content: str) -> str:
        # CSP requires the hash of the EXACT content between <script> tags
        script_bytes = script_content.encode('utf-8')
        hash_bytes = hashlib.sha256(script_bytes).digest()
        hash_b64 = base64.b64encode(hash_bytes).decode('ascii')
        return hash_b64

    def load(self, loader):
        try:
            script_dir = Path(__file__).parent.parent / 'JS'
            layer_files = {
                'preflight': script_dir / 'preflight.js',
                'config': script_dir / 'config_layer.js',
                'spoofing': script_dir / 'fingerprint_spoof.js',
                'sandbox': script_dir / 'sandbox_lockdown.js'
            }

            for layer_name, layer_path in layer_files.items():
                if not layer_path.exists():
                    ctx.log.error(f"[JSInjector] Missing {layer_name} layer: {layer_path}")
                    return

                with open(layer_path, 'r', encoding='utf-8') as f:
                    self.layers[layer_name] = f.read()

                # Compute hash for CSP
                if layer_name != 'config':  # config layer has dynamic content
                    self.layer_hashes[layer_name] = self._compute_script_hash(self.layers[layer_name])
                    ctx.log.info(f"[JSInjector] {layer_name} hash: sha256-{self.layer_hashes[layer_name][:16]}...")

                layer_size_kb = len(self.layers[layer_name]) / 1024
                ctx.log.info(f"[JSInjector] Loaded {layer_name} layer ({layer_size_kb:.1f}KB)")

            self.enabled = True
            ctx.log.info("[JSInjector] Initialized with 4-layer architecture")

        except Exception as e:
            ctx.log.error(f"[JSInjector] Initialization error: {e}")
            self.enabled = False

    def _build_config_json(self, profile: dict) -> str:
        config = {
            'name': profile.get('name', 'Unknown Profile'),
            'user_agent': profile.get('user_agent', ''),
            'platform': profile.get('platform', ''),
            'vendor': profile.get('vendor', ''),
            'vendorSub': profile.get('vendorSub', ''),
            'productSub': profile.get('productSub', '20030107'),
            'browser_type': profile.get('browser_type', 'chrome'),
            'browser_version': profile.get('browser_version', ''),
            'os': profile.get('os', ''),
            'os_version': profile.get('os_version', ''),
            'sec_ch_ua': profile.get('sec_ch_ua', ''),
            'sec_ch_ua_mobile': profile.get('sec_ch_ua_mobile', '?0'),
            'sec_ch_ua_platform': profile.get('sec_ch_ua_platform', ''),
            'sec_ch_ua_full_version': profile.get('sec_ch_ua_full_version', ''),
            'sec_ch_ua_arch': profile.get('sec_ch_ua_arch', ''),
            'sec_ch_ua_platform_version': profile.get('sec_ch_ua_platform_version', ''),
            'sec_ch_ua_bitness': profile.get('sec_ch_ua_bitness', ''),
            'hardware_concurrency': profile.get('hardware_concurrency', 8),
            'device_memory': profile.get('device_memory', 8),
            'max_touch_points': profile.get('max_touch_points', 0),
            'screen_resolution': profile.get('screen_resolution', '1920x1080'),
            'screen_avail_width': profile.get('screen_avail_width', 1920),
            'screen_avail_height': profile.get('screen_avail_height', 1040),
            'screen_avail_top': profile.get('screen_avail_top', 0),
            'screen_avail_left': profile.get('screen_avail_left', 0),
            'color_depth': profile.get('color_depth', 24),
            'pixel_depth': profile.get('pixel_depth', 24),
            'canvas_hash': profile.get('canvas_hash', ''),
            'webgl_vendor': profile.get('webgl_vendor', 'Google Inc. (Intel)'),
            'webgl_renderer': profile.get('webgl_renderer', 'ANGLE (Intel)'),
            'webgl_hash': profile.get('webgl_hash', ''),
            'audio_hash': profile.get('audio_hash', ''),
            'fonts': profile.get('fonts', []),
            'timezone_offset': profile.get('timezone_offset', 300),
            'timezone': profile.get('timezone', 'America/New_York'),
            'languages': profile.get('languages', ['en-US', 'en']),
            'do_not_track': profile.get('do_not_track', None),
            'cookie_enabled': profile.get('cookie_enabled', True),
            'webdriver': profile.get('webdriver', False),
            'plugins': profile.get('plugins', 'PDF Viewer'),
            'storage_quota': profile.get('storage_quota', 107374182400),
            'webrtc_local_ips': profile.get('webrtc_local_ips', ['192.168.1.100']),
            'enable_headers_spoof': profile.get('enable_headers_spoof', True),
            'enable_canvas_spoof': profile.get('enable_canvas_spoof', True),
            'enable_webgl_spoof': profile.get('enable_webgl_spoof', True),
            'enable_audio_spoof': profile.get('enable_audio_spoof', True),
            'enable_timezone_spoof': profile.get('enable_timezone_spoof', True),
            'enable_automation_evasion': profile.get('enable_automation_evasion', True),
            'enable_webrtc_spoof': profile.get('enable_webrtc_spoof', True),
            'enable_performance_spoof': profile.get('enable_performance_spoof', True),
            'enable_plugin_spoof': profile.get('enable_plugin_spoof', True),
            'enable_storage_spoof': profile.get('enable_storage_spoof', True),
            'enable_element_spoofing': profile.get('enable_element_spoofing', True),
            'enable_dom_evasion': profile.get('enable_dom_evasion', True),
            'enable_iframe_protection': profile.get('enable_iframe_protection', True),
            'enable_viewport_spoof': profile.get('enable_viewport_spoof', True),
            'viewport_rounding': profile.get('viewport_rounding', 200),
            'debug': self.debug
        }

        json_str = json.dumps(config, separators=(',', ':'), ensure_ascii=False)
        json_str = json_str.replace('\\', '\\\\').replace('</script>', '<\\/script>')
        return json_str

    def _build_injection(self, profile: dict, nonce: Optional[str] = None) -> tuple:
        nonce_attr = f' nonce="{nonce}"' if nonce else ''

        ctx.log.error(f"[JSI DEBUG] _build_injection() called with nonce='{nonce}'")
        if nonce:
            ctx.log.info(f"[JSInjector] Building injection with nonce attribute: nonce=\"{nonce[:12]}...\"")
        else:
            ctx.log.error("[JSI DEBUG] PROBLEM: Building injection WITHOUT nonce attribute!")

        config_json = self._build_config_json(profile)
        config_layer = self.layers['config'].replace('{{config_json}}', config_json)

        # Compute hash for the config layer now that it has dynamic content
        config_hash = self._compute_script_hash(config_layer)

        return f'''<!-- 404_REL Preflight START -->
<script{nonce_attr}>
{self.layers['preflight']}
</script>
<script{nonce_attr}>
{config_layer}
</script>
<script{nonce_attr}>
{self.layers['spoofing']}
</script>
<script{nonce_attr}>
{self.layers['sandbox']}
</script>
<!-- 404_REL Preflight END -->
''', config_hash

    def response(self, flow: http.HTTPFlow) -> None:

        ctx.log.error(f"[JSI DEBUG] response() CALLED for {flow.request.host}")

        if not self.enabled or not flow.response:
            return

        content_type = flow.response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            return

        if flow.response.status_code != 200:
            return

        profile = flow.metadata.get('fingerprint_config')
        if not profile:
            ctx.log.warn("[JSInjector] No fingerprint_config in flow.metadata")
            return

        nonce = flow.metadata.get('csp_nonce')

        ctx.log.error(f"[JSI DEBUG] Read nonce from metadata: '{nonce}'")
        ctx.log.error(f"[JSI DEBUG] All metadata keys: {list(flow.metadata.keys())}")
        ctx.log.error(f"[JSI DEBUG] Metadata values: csp_nonce={nonce}, has profile={bool(profile)}")
        if not nonce:
            ctx.log.error("[JSI DEBUG] PROBLEM: No CSP nonce found! Scripts will have empty nonce=\"\"")
        else:
            ctx.log.info(f"[JSInjector] Using nonce: {nonce[:12]}... for {flow.request.host}")

        injection, config_hash = self._build_injection(profile, nonce)

        # Store script hashes in flow.metadata for CSPModifier to use
        script_hashes = [
            self.layer_hashes.get('preflight'),
            config_hash,  # Dynamic config layer hash
            self.layer_hashes.get('spoofing'),
            self.layer_hashes.get('sandbox')
        ]
        flow.metadata['script_hashes'] = [h for h in script_hashes if h]  # Remove None values

        ctx.log.info(f"[JSInjector] Stored {len(flow.metadata['script_hashes'])} script hashes for CSP")
        ctx.log.error(f"[JSI DEBUG] Script hashes: {[h[:16]+'...' for h in flow.metadata['script_hashes']]}")

        try:
            body = flow.response.text
        except UnicodeDecodeError:
            ctx.log.error("[JSInjector] Failed to decode response as text")
            return

        patterns = ['<!DOCTYPE html>', '<!doctype html>', '<html>', '<HTML>']
        injected = False

        for pattern in patterns:
            if pattern in body:
                pos = body.find(pattern)
                body = body[:pos] + injection + body[pos:]
                injected = True
                break

        if not injected:
            body = injection + body

        flow.response.text = body
        flow.response.headers["Content-Length"] = str(len(flow.response.content))

        self.inject_count += 1
        if self.debug:
            ctx.log.info(f"[JSInjector] Injected into {flow.request.pretty_url[:60]}")

addons = [JSInjector()]