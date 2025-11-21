""" Deep TLS Hook Addon for mitmproxy

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

"""
EXPERIMENTAL: Deep hook into mitmproxy's TLS layer using pyOpenSSL.

This addon attempts to monkey-patch mitmproxy's internal TLS context creation
to inject custom cipher suites. This is HIGHLY experimental and may break
with mitmproxy updates.

Approach:
1. Patch OpenSSL.SSL.Context creation
2. Intercept set_cipher_list() calls
3. Inject Firefox/Chrome cipher ordering
"""

from mitmproxy import ctx
from typing import Dict, Any, Optional, Iterable, Tuple, List
import OpenSSL.SSL as SSL
import hashlib
import random
import secrets
import time

# TLS config cache (populated by HeaderProfileAddon)
_TLS_CONFIG_CACHE: Dict[str, Dict[str, Any]] = {}

def set_tls_config_for_host(hostname: str, tls_config: Dict[str, Any]):
    """Called by HeaderProfileAddon to cache TLS config for a hostname"""
    global _TLS_CONFIG_CACHE
    _TLS_CONFIG_CACHE[hostname] = tls_config
    ctx.log.debug(f"[TLS-DEEP] Cached TLS config for {hostname}")

def get_tls_config_for_host(hostname: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached TLS config for a hostname"""
    return _TLS_CONFIG_CACHE.get(hostname)


class TLSDeepHook:
    """
    Experimental deep hook into mitmproxy's TLS layer.
    
    WARNING: This patches OpenSSL directly and may be unstable.
    """
    
    def __init__(self):
        self.enabled = True
        self.patched = False
        self.original_context_init = None
        self.original_set_cipher_list = None
        self.stats = {
            'contexts_created': 0,
            'cipher_lists_set': 0,
            'patches_applied': 0,
        }

        # Rotate cipher bundles roughly every 5 minutes per host/profile pair.
        self.rotation_window_seconds = 300

        # RFC-compliant cipher allowlist to preserve PFS.
        # Only TLS 1.3 suites and TLS 1.2 ECDHE suites are accepted.
        self.safe_cipher_allowlist = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        }

        self.default_safe_iana = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ]

        self.tls13_preference = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ]
        self.tls13_names = set(self.tls13_preference)
        self.default_tls12_iana = [cipher for cipher in self.default_safe_iana if cipher not in self.tls13_names]
        
        # Cipher suite mapping (IANA names to OpenSSL names)
        self.cipher_map = {
            # TLS 1.3 ciphers
            "TLS_AES_128_GCM_SHA256": "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384": "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
            
            # TLS 1.2 ECDHE ciphers
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHE-ECDSA-AES128-GCM-SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHE-RSA-AES256-GCM-SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-RSA-CHACHA20-POLY1305",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": "ECDHE-ECDSA-AES128-SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "ECDHE-RSA-AES128-SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": "ECDHE-ECDSA-AES256-SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": "ECDHE-RSA-AES256-SHA",
            
            # TLS 1.2 RSA ciphers
            "TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA256": "AES128-SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256": "AES256-SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA": "AES128-SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA": "AES256-SHA",
        }

        self.default_tls13_string = self._convert_cipher_list(self.tls13_preference)
        self.default_tls12_string = self._convert_cipher_list(self.default_tls12_iana)
        self.default_cipher_string = self._convert_cipher_list(self.default_safe_iana)

        ctx.log.warn("[TLS-DEEP] EXPERIMENTAL TLS DEEP HOOK INITIALIZED")
        ctx.log.warn("[TLS-DEEP] This patches OpenSSL directly - use at own risk")
        ctx.log.warn("[TLS-DEEP] May break with mitmproxy updates")
        
        # Apply patches on init
        self._apply_patches()
    
    def _convert_cipher_list(self, iana_ciphers: Iterable[str]) -> str:
        """Convert IANA cipher names to OpenSSL cipher string"""
        openssl_ciphers = []
        for cipher in iana_ciphers:
            openssl_name = self.cipher_map.get(cipher, cipher)
            openssl_ciphers.append(openssl_name)
        return ":".join(openssl_ciphers)

    def _filter_safe_ciphers(self, hostname: str, cipher_list: Iterable[str]) -> Iterable[str]:
        """Yield only safe, PFS-capable cipher suites."""
        safe = []
        for cipher in cipher_list:
            if cipher in self.safe_cipher_allowlist:
                safe.append(cipher)
            else:
                ctx.log.warn(
                    f"[TLS-DEEP] Dropping insecure cipher '{cipher}' for {hostname}. "
                    "Only PFS suites are permitted."
                )
        return safe

    def _choose_rotating_cipher_list(
        self,
        hostname: str,
        tls_config: Optional[Dict[str, Any]],
        entropy_token: str
    ) -> Tuple[Optional[Iterable[str]], Optional[Dict[str, Any]]]:
        """Select a cipher rotation entry if defined for the profile."""
        if not tls_config:
            return None, None

        rotations = tls_config.get('cipher_rotations')
        if not isinstance(rotations, (list, tuple)):
            return None, None

        valid_rotations: List[Tuple[List[str], Dict[str, Any]]] = []
        for idx, rotation in enumerate(rotations):
            cipher_candidates = None
            rotation_meta: Dict[str, Any] = {'index': idx}

            if isinstance(rotation, dict):
                cipher_candidates = (
                    rotation.get('ciphers')
                    or rotation.get('cipher_suites')
                    or rotation.get('list')
                )
                rotation_meta['label'] = rotation.get('label')
                rotation_meta['shuffle'] = rotation.get('shuffle')
                rotation_meta['shuffle_groups'] = rotation.get('shuffle_groups')
            elif isinstance(rotation, (list, tuple)):
                cipher_candidates = rotation
            else:
                continue

            if not cipher_candidates:
                continue

            sanitized = [cipher for cipher in cipher_candidates if isinstance(cipher, str)]
            if sanitized:
                valid_rotations.append((sanitized, rotation_meta))

        if not valid_rotations:
            return None, None

        profile_name = tls_config.get('_profile_name', 'unknown')
        seed_material = f"{hostname}|{profile_name}|{entropy_token}"
        seed_bytes = seed_material.encode('utf-8', errors='ignore')
        deterministic_seed = int(hashlib.sha256(seed_bytes).hexdigest(), 16)
        rng = random.Random(deterministic_seed)
        cipher_list, rotation_meta = rng.choice(valid_rotations)
        return cipher_list, rotation_meta

    def _infer_cipher_groups(self, cipher_list: Iterable[str]) -> List[List[str]]:
        """Split cipher list into TLS 1.3, TLS 1.2 modern, and TLS 1.2 legacy buckets."""
        tls13: List[str] = []
        tls12_modern: List[str] = []
        tls12_legacy: List[str] = []

        for cipher in cipher_list:
            upper = cipher.upper()
            if upper.startswith("TLS_AES") or upper.startswith("TLS_CHACHA20"):
                tls13.append(cipher)
            elif "GCM" in upper or "CHACHA20" in upper:
                tls12_modern.append(cipher)
            else:
                tls12_legacy.append(cipher)

        groups: List[List[str]] = []
        if tls13:
            groups.append(tls13)
        if tls12_modern:
            groups.append(tls12_modern)
        if tls12_legacy:
            groups.append(tls12_legacy)
        return groups

    def _shuffle_cipher_order(
        self,
        safe_ciphers: Iterable[str],
        rotation_meta: Optional[Dict[str, Any]]
    ) -> Tuple[List[str], bool]:
        """Randomize cipher order within rotation groups to mimic browser variability."""
        if not rotation_meta:
            return list(safe_ciphers), False

        shuffle_mode = rotation_meta.get('shuffle')
        if not shuffle_mode:
            return list(safe_ciphers), False

        if isinstance(shuffle_mode, str):
            strategy = shuffle_mode.lower()
        else:
            strategy = 'full' if shuffle_mode else None

        if not strategy:
            return list(safe_ciphers), False

        ciphers = list(safe_ciphers)
        rng = random.SystemRandom()

        if strategy == 'full':
            rng.shuffle(ciphers)
            return ciphers, True

        if strategy == 'groups':
            groups = rotation_meta.get('shuffle_groups')
            if not groups:
                groups = self._infer_cipher_groups(ciphers)

            new_order: List[str] = []
            seen = set()

            for group in groups:
                if isinstance(group, dict):
                    group_list = [c for c in group.get('ciphers', []) if isinstance(c, str)]
                else:
                    group_list = [c for c in group if isinstance(c, str)]

                subset = [cipher for cipher in ciphers if cipher in group_list and cipher not in seen]
                if not subset:
                    continue
                rng.shuffle(subset)
                new_order.extend(subset)
                seen.update(subset)

            for cipher in ciphers:
                if cipher not in seen:
                    new_order.append(cipher)

            return new_order, True

        return ciphers, False

    def _build_cipher_string(
        self,
        hostname: str,
        tls_config: Optional[Dict[str, Any]],
        entropy_token: str
    ) -> Tuple[Optional[Dict[str, Optional[str]]], Dict[str, Any]]:
        """Determine safest cipher plan for a host, falling back to defaults."""
        meta = {
            'source': 'default',
            'rotation_index': None,
            'rotation_label': None,
            'shuffle': None,
            'shuffle_applied': False,
            'tls13_count': 0,
            'tls12_count': 0,
        }
        requested: Iterable[str] = []

        rotation_list, rotation_meta = self._choose_rotating_cipher_list(hostname, tls_config, entropy_token)
        if rotation_list:
            requested = rotation_list
            meta['source'] = 'rotation'
            meta['rotation_index'] = (rotation_meta or {}).get('index')
            meta['rotation_label'] = (rotation_meta or {}).get('label')
            meta['shuffle'] = (rotation_meta or {}).get('shuffle')
        elif tls_config:
            requested = tls_config.get('cipher_suites', []) or []
            if requested:
                meta['source'] = 'profile'

        if not requested:
            requested = self.default_safe_iana

        safe_ciphers = self._filter_safe_ciphers(hostname, requested)
        if not safe_ciphers:
            ctx.log.warn(
                f"[TLS-DEEP] No safe ciphers remain for {hostname}; enforcing default allowlist"
            )
            safe_ciphers = self.default_safe_iana
            meta['source'] = 'default'
            meta['rotation_index'] = None
            rotation_meta = None

        shuffled_ciphers, shuffle_applied = self._shuffle_cipher_order(safe_ciphers, rotation_meta)
        if shuffle_applied:
            safe_ciphers = shuffled_ciphers
            meta['shuffle_applied'] = True

        tls13_list = [cipher for cipher in safe_ciphers if cipher in self.tls13_names]
        legacy_list = [cipher for cipher in safe_ciphers if cipher not in self.tls13_names]

        meta['tls13_count'] = len(tls13_list)
        meta['tls12_count'] = len(legacy_list)

        cipher_plan = {
            'tls13': self._convert_cipher_list(tls13_list) if tls13_list else None,
            'tls12': self._convert_cipher_list(legacy_list) if legacy_list else None,
        }

        if not cipher_plan['tls13'] and not cipher_plan['tls12']:
            ctx.log.error(
                f"[TLS-DEEP] Failed to construct cipher plan for {hostname} (source={meta['source']})"
            )
            return None, meta

        return cipher_plan, meta

    def _resolve_hostname(self, data) -> str:
        hostname = None
        if hasattr(data.conn, 'sni') and data.conn.sni:
            hostname = data.conn.sni
        elif hasattr(data.conn, 'address') and data.conn.address:
            hostname = data.conn.address[0] if isinstance(data.conn.address, tuple) else str(data.conn.address)
        return hostname or 'unknown-host'

    def _handshake_entropy(self, data) -> str:
        tokens: List[str] = []
        if hasattr(data, 'flow') and getattr(data.flow, 'id', None):
            tokens.append(str(data.flow.id))
        if hasattr(data, 'conn') and getattr(data.conn, 'id', None):
            tokens.append(str(data.conn.id))
        tokens.append(str(time.time_ns()))
        tokens.append(secrets.token_hex(8))
        return "|".join(tokens)

    def _enforce_fallback_ciphers(self, ssl_context, hostname: str):
        try:
            tls13_applied = False
            if hasattr(ssl_context, 'set_ciphersuites') and self.default_tls13_string:
                try:
                    ssl_context.set_ciphersuites(self.default_tls13_string)
                    tls13_applied = True
                except Exception as tls13_error:
                    ctx.log.warn(
                        f"[TLS-DEEP] TLS1.3 fallback failed for {hostname}: {tls13_error}"
                    )

            legacy_string = self.default_tls12_string or self.default_cipher_string
            ssl_context.set_cipher_list(legacy_string.encode('utf-8'))
            note = "TLS1.3/TLS1.2" if tls13_applied else "TLS1.2"
            ctx.log.warn(
                f"[TLS-DEEP] Applied fallback {note} cipher policy for {hostname}"
            )
        except Exception as fallback_error:
            ctx.log.error(
                f"[TLS-DEEP] Fallback cipher enforcement failed for {hostname}: {fallback_error}"
            )
    
    def _apply_patches(self):
        """
        Monkey-patch OpenSSL.SSL.Context to inject custom cipher suites.
        
        This is the nuclear option - we're patching OpenSSL directly.
        """
        if self.patched:
            return
        
        try:
            # Store original methods
            self.original_context_init = SSL.Context.__init__
            self.original_set_cipher_list = SSL.Context.set_cipher_list
            
            # Create our patched version
            addon_self = self  # Capture self in closure
            
            def patched_context_init(ssl_context_self, method):
                """Patched Context.__init__"""
                addon_self.stats['contexts_created'] += 1
                ctx.log.debug(f"[TLS-DEEP] Context created (total: {addon_self.stats['contexts_created']})")
                
                # Call original init
                return addon_self.original_context_init(ssl_context_self, method)
            
            def patched_set_cipher_list(ssl_context_self, cipher_string):
                """Patched Context.set_cipher_list()"""
                addon_self.stats['cipher_lists_set'] += 1
                
                # Try to get hostname from stack trace or use default config
                # This is hacky but works - we'll look for cached config
                
                # For now, just log and pass through
                ctx.log.debug(f"[TLS-DEEP] set_cipher_list called: {cipher_string[:60]}...")
                
                # TODO: Check if we have a custom cipher list for this connection
                # For now, pass through to original
                return addon_self.original_set_cipher_list(ssl_context_self, cipher_string)
            
            # Apply patches
            SSL.Context.__init__ = patched_context_init
            SSL.Context.set_cipher_list = patched_set_cipher_list
            
            self.patched = True
            self.stats['patches_applied'] += 1
            
            ctx.log.info("[TLS-DEEP] Successfully patched OpenSSL.SSL.Context")
            ctx.log.info("[TLS-DEEP] Cipher suite injection is now active")
            
        except Exception as e:
            ctx.log.error(f"[TLS-DEEP] Failed to apply patches: {e}")
            import traceback
            ctx.log.error(f"[TLS-DEEP] Traceback: {traceback.format_exc()}")
    
    def tls_start_client(self, data):
        """
        Hook that fires before TLS handshake.
        
        At this point, we can try to get the SSL context and modify it.
        """
        if not self.enabled:
            return
        
        try:
            hostname = self._resolve_hostname(data)
            entropy_token = self._handshake_entropy(data)

            tls_config = get_tls_config_for_host(hostname)
            profile_name = (tls_config or {}).get('_profile_name', 'default-safe')

            if not hasattr(data, 'ssl_conn') or not data.ssl_conn:
                ctx.log.debug(f"[TLS-DEEP] No ssl_conn available for {hostname}; cannot enforce ciphers")
                return

            ssl_conn = data.ssl_conn
            if not hasattr(ssl_conn, 'get_context'):
                ctx.log.debug(f"[TLS-DEEP] SSL connection lacks context accessor for {hostname}")
                return

            ssl_context = ssl_conn.get_context()
            if not ssl_context:
                ctx.log.debug(f"[TLS-DEEP] Context unavailable for {hostname}")
                return

            cipher_plan, cipher_meta = self._build_cipher_string(hostname, tls_config, entropy_token)
            if not cipher_plan:
                self._enforce_fallback_ciphers(ssl_context, hostname)
                return

            tls13_string = cipher_plan.get('tls13')
            legacy_string = cipher_plan.get('tls12')
            tls13_applied = False
            legacy_applied = False

            if tls13_string and hasattr(ssl_context, 'set_ciphersuites'):
                try:
                    ssl_context.set_ciphersuites(tls13_string)
                    tls13_applied = True
                except Exception as tls13_error:
                    ctx.log.warn(
                        f"[TLS-DEEP] Failed to set TLS1.3 suites for {hostname}: {tls13_error}"
                    )

            if legacy_string:
                try:
                    ssl_context.set_cipher_list(legacy_string.encode('utf-8'))
                    legacy_applied = True
                except Exception as legacy_error:
                    ctx.log.error(
                        f"[TLS-DEEP] Failed to set TLS1.2 suites for {hostname}: {legacy_error}"
                    )

            if not tls13_applied and not legacy_applied:
                self._enforce_fallback_ciphers(ssl_context, hostname)
                return

            rotation_note = ""
            if cipher_meta.get('rotation_index') is not None:
                rotation_note = f", rotation={cipher_meta['rotation_index']}"
            shuffle_note = ""
            if cipher_meta.get('shuffle_applied'):
                shuffle_note = f", shuffle={cipher_meta.get('shuffle', 'groups')}"
            coverage_note = []
            if tls13_applied:
                coverage_note.append("TLS1.3")
            if legacy_applied:
                coverage_note.append("TLS1.2")
            coverage_label = "/".join(coverage_note) if coverage_note else "none"

            ctx.log.info(
                f"[TLS-DEEP] Applied {coverage_label} ciphers for {hostname} (profile: {profile_name}{rotation_note}{shuffle_note})"
            )
            ctx.log.debug(
                f"[TLS-DEEP] Cipher meta source={cipher_meta.get('source')} plan={cipher_plan}"
            )
            
        except Exception as e:
            ctx.log.error(f"[TLS-DEEP] Error in tls_start_client: {e}")
            import traceback
            ctx.log.error(f"[TLS-DEEP] Traceback: {traceback.format_exc()}")
    
    def tls_established_client(self, data):
        """Log established TLS connections"""
        if not self.enabled:
            return
        
        try:
            # Get hostname
            hostname = "unknown"
            if hasattr(data.conn, 'sni') and data.conn.sni:
                hostname = data.conn.sni
            elif hasattr(data.conn, 'address') and data.conn.address:
                hostname = data.conn.address[0] if isinstance(data.conn.address, tuple) else str(data.conn.address)
            
            # Get TLS version and cipher
            tls_version = "unknown"
            cipher_suite = "unknown"
            
            try:
                if hasattr(data, 'ssl_conn') and data.ssl_conn:
                    # Get cipher info
                    cipher_info = data.ssl_conn.get_cipher_name()
                    if cipher_info:
                        cipher_suite = cipher_info
                    
                    # Get TLS version
                    version_info = data.ssl_conn.get_protocol_version_name()
                    if version_info:
                        tls_version = version_info
            except:
                pass
            
            # Get profile info
            tls_config = get_tls_config_for_host(hostname)
            profile_name = "unknown"
            if tls_config:
                profile_name = tls_config.get('_profile_name', 'unknown')
            
            ctx.log.info(
                f"[TLS-DEEP ESTABLISHED] {hostname} -> "
                f"{tls_version} | Cipher: {cipher_suite} | Profile: {profile_name}"
            )
            
        except Exception as e:
            ctx.log.error(f"[TLS-DEEP] Error in tls_established_client: {e}")
    
    def done(self):
        """Log statistics and restore patches"""
        ctx.log.info("[TLS-DEEP] Statistics:")
        ctx.log.info(f"  Contexts created: {self.stats['contexts_created']}")
        ctx.log.info(f"  Cipher lists set: {self.stats['cipher_lists_set']}")
        ctx.log.info(f"  Patches applied: {self.stats['patches_applied']}")
        
        # Restore original methods
        if self.patched and self.original_context_init:
            try:
                SSL.Context.__init__ = self.original_context_init
                SSL.Context.set_cipher_list = self.original_set_cipher_list
                ctx.log.info("[TLS-DEEP] Patches restored")
            except Exception as e:
                ctx.log.error(f"[TLS-DEEP] Failed to restore patches: {e}")


addons = [TLSDeepHook()]
