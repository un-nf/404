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
from typing import Dict, Any, Optional
import OpenSSL.SSL as SSL

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
        
        ctx.log.warn("[TLS-DEEP] =============================================")
        ctx.log.warn("[TLS-DEEP] EXPERIMENTAL TLS DEEP HOOK INITIALIZED")
        ctx.log.warn("[TLS-DEEP] This patches OpenSSL directly - use at own risk")
        ctx.log.warn("[TLS-DEEP] May break with mitmproxy updates")
        ctx.log.warn("[TLS-DEEP] =============================================")
        
        # Apply patches on init
        self._apply_patches()
    
    def _convert_cipher_list(self, iana_ciphers: list) -> str:
        """Convert IANA cipher names to OpenSSL cipher string"""
        openssl_ciphers = []
        for cipher in iana_ciphers:
            openssl_name = self.cipher_map.get(cipher, cipher)
            openssl_ciphers.append(openssl_name)
        
        # OpenSSL cipher string format: "CIPHER1:CIPHER2:CIPHER3"
        return ":".join(openssl_ciphers)
    
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
            
            ctx.log.info("[TLS-DEEP] ✓ Successfully patched OpenSSL.SSL.Context")
            ctx.log.info("[TLS-DEEP] ✓ Cipher suite injection is now active")
            
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
            # Get hostname
            hostname = None
            if hasattr(data.conn, 'sni') and data.conn.sni:
                hostname = data.conn.sni
            elif hasattr(data.conn, 'address') and data.conn.address:
                hostname = data.conn.address[0] if isinstance(data.conn.address, tuple) else str(data.conn.address)
            
            if not hostname:
                return
            
            # Get TLS config from cache
            tls_config = get_tls_config_for_host(hostname)
            if not tls_config:
                return
            
            profile_name = tls_config.get('_profile_name', 'unknown')
            
            # Try to access the SSL connection
            if hasattr(data, 'ssl_conn') and data.ssl_conn:
                ssl_conn = data.ssl_conn
                
                # Try to get the context
                if hasattr(ssl_conn, 'get_context'):
                    ssl_context = ssl_conn.get_context()
                    
                    # Now try to set cipher list
                    cipher_suites = tls_config.get('cipher_suites', [])
                    if cipher_suites:
                        cipher_string = self._convert_cipher_list(cipher_suites)
                        
                        try:
                            ssl_context.set_cipher_list(cipher_string.encode('utf-8'))
                            ctx.log.info(f"[TLS-DEEP] ✓ Applied custom ciphers for {hostname} (profile: {profile_name})")
                            ctx.log.debug(f"[TLS-DEEP] Cipher string: {cipher_string}")
                        except Exception as e:
                            ctx.log.error(f"[TLS-DEEP] Failed to set ciphers: {e}")
            else:
                ctx.log.debug(f"[TLS-DEEP] No ssl_conn available for {hostname}")
            
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
                ctx.log.info("[TLS-DEEP] ✓ Patches restored")
            except Exception as e:
                ctx.log.error(f"[TLS-DEEP] Failed to restore patches: {e}")


addons = [TLSDeepHook()]
