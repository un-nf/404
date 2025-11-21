""" TLS Profile Addon for mitmproxy

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

from mitmproxy import ctx
from typing import Dict, Any, Optional, List
import hashlib
import random
import time

try:
    from AOs.tls_mitm_patcher import TLSMitmPatcher, TLSConfig, install_tls_patches
except ImportError:
    ctx.log.error("[TLS-PROFILE] Failed to import TLS patcher - ensure tls_mitm_patcher.py exists")
    raise


class TLSProfileAddon:

    def __init__(self):
        self.patcher: Optional[TLSMitmPatcher] = None
        self.enabled = True
        
        self.rotation_window_seconds = 300  # 5 minutes
        
        self.stats = {
            'connections_total': 0,
            'connections_configured': 0,
            'profiles_applied': 0,
            'rotations_performed': 0,
        }

    
    def load(self, loader):
   
        try:
            self.patcher = install_tls_patches()
            self.patcher.set_cipher_callback(self._get_tls_config)
        except Exception as e:
            ctx.log.error(f"[TLS-PROFILE] Failed to install patcher: {e}")
            self.enabled = False
    
    def _get_tls_config(self, hostname: str, sni: str) -> Optional[TLSConfig]:

        if not self.enabled:
            return None
        
        try:
            # Get profile from flow metadata (set by HeaderProfileAddon)
            
            # For now, use a default profile lookup
            # In production, HeaderProfileAddon should cache this
            profile_data = self._get_profile_for_host(hostname)
            
            if not profile_data:
                ctx.log.debug(f"[TLS-PROFILE] No profile for {hostname}, using defaults")
                return None
            
            tls_config_data = profile_data.get('tls', {})
            
            if not tls_config_data:
                ctx.log.debug(f"[TLS-PROFILE] No TLS config in profile for {hostname}")
                return None
            
            cipher_suites = self._select_cipher_suites(hostname, tls_config_data)
            
            if not cipher_suites:
                ctx.log.debug(f"[TLS-PROFILE] No cipher suites selected for {hostname}")
                return None
            
            config = TLSConfig(
                cipher_suites=cipher_suites,
                tls_versions=tls_config_data.get('versions', ("TLSv1.2", "TLSv1.3")),
                curves=tls_config_data.get('curves', []),
                signature_algorithms=tls_config_data.get('signature_algorithms', []),
                alpn_protocols=tls_config_data.get('alpn', ["h2", "http/1.1"])
            )
            config.profile_name = profile_data.get('_profile_name', 'unknown')
            
            self.stats['connections_configured'] += 1
            self.stats['profiles_applied'] += 1
            
            return config
            
        except Exception as e:
            ctx.log.error(f"[TLS-PROFILE] Error getting config for {hostname}: {e}")
            import traceback
            ctx.log.error(f"[TLS-PROFILE] Traceback: {traceback.format_exc()}")
            return None
    
    def _get_profile_for_host(self, hostname: str) -> Optional[Dict[str, Any]]:

        # TODO: Integrate with HeaderProfileAddon
        # For now, return None to use defaults
        return None
    
    def _select_cipher_suites(self, hostname: str, tls_config: Dict[str, Any]) -> Optional[List[str]]:

        cipher_rotations = tls_config.get('cipher_rotations', [])
        
        if cipher_rotations:
            self.stats['rotations_performed'] += 1
            return self._rotate_cipher_suites(hostname, cipher_rotations, tls_config)
        
        cipher_suites = tls_config.get('cipher_suites', [])
        
        if not cipher_suites:
            cipher_suites = tls_config.get('ciphers', [])
        
        return cipher_suites if cipher_suites else None
    
    def _rotate_cipher_suites(self, 
                              hostname: str, 
                              rotations: List[Any],
                              tls_config: Dict[str, Any]) -> Optional[List[str]]:

        if not rotations:
            return None
        
        # Calculate rotation entropy token
        time_bucket = int(time.time() // self.rotation_window_seconds)
        profile_name = tls_config.get('_profile_name', 'unknown')
        
        # Create deterministic seed
        seed_material = f"{hostname}|{profile_name}|{time_bucket}"
        seed_bytes = seed_material.encode('utf-8')
        deterministic_seed = int(hashlib.sha256(seed_bytes).hexdigest(), 16)
        
        rng = random.Random(deterministic_seed)
        
        valid_rotations = []
        for rotation in rotations:
            if isinstance(rotation, dict):
                ciphers = rotation.get('ciphers') or rotation.get('cipher_suites') or rotation.get('list')
                if ciphers and isinstance(ciphers, list):
                    valid_rotations.append({
                        'ciphers': ciphers,
                        'shuffle': rotation.get('shuffle', False),
                        'label': rotation.get('label', 'unlabeled')
                    })
            elif isinstance(rotation, list):
                valid_rotations.append({
                    'ciphers': rotation,
                    'shuffle': False,
                    'label': 'unlabeled'
                })
        
        if not valid_rotations:
            ctx.log.warn(f"[TLS-PROFILE] No valid rotations found for {hostname}")
            return None
        
        selected = rng.choice(valid_rotations)
        ciphers = list(selected['ciphers'])
        
        if selected.get('shuffle'):
            rng.shuffle(ciphers)
            ctx.log.debug(f"[TLS-PROFILE] Shuffled cipher list for {hostname}")
        
        ctx.log.debug(f"[TLS-PROFILE] Selected rotation '{selected['label']}' for {hostname} ({len(ciphers)} ciphers)")
        
        return ciphers
    
    def tls_start_client(self, data):

        if not self.enabled or not self.patcher:
            return
        
        self.stats['connections_total'] += 1
        
        try:
            # Extract hostname/SNI
            # In mitmproxy, we need to get this from the connection
            hostname = data.sni if hasattr(data, 'sni') else None
            sni = data.sni if hasattr(data, 'sni') else ""
            
            if not hostname:
                ctx.log.debug("[TLS-PROFILE] No SNI available, skipping configuration")
                return
            
            self.patcher.set_connection_config(hostname, sni)
            
        except Exception as e:
            ctx.log.error(f"[TLS-PROFILE] Error in tls_start_client: {e}")
            import traceback
            ctx.log.error(f"[TLS-PROFILE] Traceback: {traceback.format_exc()}")
    
    def tls_established_client(self, data):

        if not self.enabled or not self.patcher:
            return
        
        try:
            if hasattr(data, 'tls_established') and data.tls_established:
                cipher = getattr(data, 'cipher', 'unknown')
                tls_version = getattr(data, 'tls_version', 'unknown')
                sni = data.sni if hasattr(data, 'sni') else 'unknown'
            
            self.patcher.clear_connection_config()
            
        except Exception as e:
            ctx.log.error(f"[TLS-PROFILE] Error in tls_established_client: {e}")
    
    def done(self):

        pass


addons = [TLSProfileAddon()]
