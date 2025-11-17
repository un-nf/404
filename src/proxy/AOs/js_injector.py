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

import json        
import os          
import hashlib     
import base64      
import re          
from pathlib import Path         
from typing import Optional      
from mitmproxy import ctx, http  

class JSInjector:

    def __init__(self):


        self.debug = os.getenv('FINGERPRINT_DEBUG', '0').lower() in ('1', 'true', 'yes')

        self.enabled = False

        self.layers = {}

        self.layer_hashes = {}

        self.inject_count = 0

        if self.debug:
            ctx.log.info("[JSInjector] Debug mode ENABLED via FINGERPRINT_DEBUG environment variable")

    def _minify_js(self, js_code: str) -> str:

        js_code = re.sub(r'(?<!:)//[^\n]*', '', js_code)

        js_code = re.sub(r'/\*.*?\*/', '', js_code, flags=re.DOTALL)

        lines = [line.strip() for line in js_code.split('\n')]

        lines = [line for line in lines if line]

        js_code = '\n'.join(lines)

        return js_code

    def _compute_script_hash(self, script_content: str) -> str:
    
        script_bytes = script_content.encode('utf-8')
        hash_bytes = hashlib.sha256(script_bytes).digest()
        hash_b64 = base64.b64encode(hash_bytes).decode('ascii')
        return hash_b64

    def load(self, loader):
    
        try:

            script_dir = Path(__file__).parent.parent / 'JS'

            layer_files = {
                'boot': script_dir / '0bootstrap.js',                     
                'shim': script_dir / '1globals_shim.js',                     
                'config': script_dir / 'config_layer.js',           
                'spoofing': script_dir / '2fingerprint_spoof_v2.js'  
            }

            missing_files = []
            for layer_name, layer_path in layer_files.items():
                if not layer_path.exists():
                    missing_files.append(f"{layer_name}: {layer_path}")

            if missing_files:
                ctx.log.error(f"[JSInjector] Missing required files:")
                for missing in missing_files:
                    ctx.log.error(f"[JSInjector]   - {missing}")
                ctx.log.error(f"[JSInjector] Script directory: {script_dir}")
                ctx.log.error(f"[JSInjector] Files in directory:")
                try:
                    for file in script_dir.iterdir():
                        ctx.log.error(f"[JSInjector]     - {file.name}")
                except Exception as e:
                    ctx.log.error(f"[JSInjector]     Could not list directory: {e}")
                return  

            for layer_name, layer_path in layer_files.items():

                with open(layer_path, 'r', encoding='utf-8') as f:
                    original_code = f.read()

                original_size_kb = len(original_code) / 1024

                minified_code = self._minify_js(original_code)
                minified_size_kb = len(minified_code) / 1024
                reduction_pct = ((original_size_kb - minified_size_kb) / original_size_kb) * 100

                self.layers[layer_name] = minified_code

                if layer_name != 'config':  
                    self.layer_hashes[layer_name] = self._compute_script_hash(self.layers[layer_name])
                    ctx.log.info(f"[JSInjector] {layer_name} hash: sha256-{self.layer_hashes[layer_name][:16]}...")

                ctx.log.info(f"[JSInjector] Loaded {layer_name}: {original_size_kb:.1f}KB → {minified_size_kb:.1f}KB ({reduction_pct:.1f}% reduction)")

            self.enabled = True
            ctx.log.info("[JSInjector] Initialized with 4-layer priority architecture")
            ctx.log.info("[JSInjector] bootstrap.js will execute FIRST before any page content")

        except Exception as e:
            ctx.log.error(f"[JSInjector] ✗ Initialization error: {e}")
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

        config_json = self._build_config_json(profile)
        config_layer = self.layers['config'].replace('{{config_json}}', config_json)

        config_hash = self._compute_script_hash(config_layer)

        injection = (
            f'<script{nonce_attr}>{self.layers["boot"]}</script>\n'
            f'<script{nonce_attr}>{self.layers["shim"]}</script>\n'
            f'<script{nonce_attr}>{config_layer}</script>\n'
            f'<script{nonce_attr}>{self.layers["spoofing"]}</script>\n'
        )

        return injection, config_hash

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.enabled or not flow.response:
            return

        content_type = flow.response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            return

        if flow.response.status_code != 200:
            return

        profile = flow.metadata.get('fingerprint_config')
        if not profile:
            if self.debug:
                ctx.log.debug(f"[JSI] No profile for {flow.request.host}")
            return

        nonce = flow.metadata.get('csp_nonce')
        if self.debug and nonce:
            ctx.log.debug(f"[JSI] Using nonce {nonce[:8]}... for injection")

        injection, config_hash = self._build_injection(profile, nonce)

        script_hashes = [
            self.layer_hashes.get('boot'),      
            self.layer_hashes.get('shim'),      
            config_hash,                        
            self.layer_hashes.get('spoofing')   
        ]

        flow.metadata['script_hashes'] = [h for h in script_hashes if h]
        
        if self.debug:
            ctx.log.debug(f"[JSI] Stored {len(flow.metadata['script_hashes'])} hashes for CSP")

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
            ctx.log.debug(f"[JSI] Injected #{self.inject_count}: {flow.request.host}")


addons = [JSInjector()]