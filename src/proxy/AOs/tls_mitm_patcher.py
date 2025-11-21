""" mitmproxy TLS patch

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
mitmproxy tls patch

This module patches mitmproxy's TLS layer at:
1. Direct hook into mitmproxy.net.tls module
2. pyOpenSSL Context wrapper
3. stdlib ssl.SSLContext wrapper
4. Dynamic per-connection cipher suite selection
"""

from mitmproxy import ctx
from typing import Dict, Any, Optional, Callable, List, Set, Tuple
import ssl
import threading
import traceback
import hashlib
import random

_thread_local = threading.local()


class TLSConfig:
    
    def __init__(self, 
                 cipher_suites: Optional[List[str]] = None,
                 tls_versions: Optional[Tuple[str, str]] = None,
                 curves: Optional[List[str]] = None,
                 signature_algorithms: Optional[List[str]] = None,
                 alpn_protocols: Optional[List[str]] = None):

        self.cipher_suites = cipher_suites or []
        self.tls_versions = tls_versions or ("TLSv1.2", "TLSv1.3")
        self.curves = curves or []
        self.signature_algorithms = signature_algorithms or []
        self.alpn_protocols = alpn_protocols or ["h2", "http/1.1"]
        
        self.profile_name: Optional[str] = None
        self.hostname: Optional[str] = None


class CipherMapper:

    IANA_TO_OPENSSL = {
        # TLS 1.3 ciphers
        "TLS_AES_128_GCM_SHA256": "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384": "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256": "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256": "TLS_AES_128_CCM_8_SHA256",
        
        # TLS 1.2 ECDHE ciphers (PFS)
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
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": "ECDHE-ECDSA-AES128-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": "ECDHE-RSA-AES128-SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": "ECDHE-ECDSA-AES256-SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": "ECDHE-RSA-AES256-SHA384",
        
        # TLS 1.2 DHE ciphers (PFS)
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": "DHE-RSA-AES128-GCM-SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": "DHE-RSA-AES256-GCM-SHA384",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "DHE-RSA-CHACHA20-POLY1305",
        
        # TLS 1.2 RSA ciphers (no PFS - not recommended)
        "TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA256": "AES128-SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA256": "AES256-SHA256",
        "TLS_RSA_WITH_AES_128_CBC_SHA": "AES128-SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA": "AES256-SHA",
    }
    
    PFS_CIPHERS = {
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
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    }
    
    @classmethod
    def iana_to_openssl(cls, iana_names: List[str], pfs_only: bool = True) -> str:

        openssl_names = []
        for iana_name in iana_names:
            if pfs_only and iana_name not in cls.PFS_CIPHERS:
                ctx.log.warn(f"[TLS-PATCHER] Skipping non-PFS cipher: {iana_name}")
                continue
                
            openssl_name = cls.IANA_TO_OPENSSL.get(iana_name)
            if openssl_name:
                openssl_names.append(openssl_name)
            else:
                ctx.log.warn(f"[TLS-PATCHER] Unknown IANA cipher: {iana_name}")
        
        return ":".join(openssl_names)


class TLSMitmPatcher:
    """
    Patches at:
    1. stdlib ssl.SSLContext
    2. pyOpenSSL SSL.Context
    3. mitmproxy.net.tls (if available)
    """
    
    def __init__(self):
        self.installed = False
        self.cipher_callback: Optional[Callable[[str, str], Optional[TLSConfig]]] = None
        
        self._originals = {}
        
        self.stats = {
            'contexts_created': 0,
            'contexts_configured': 0,
            'cipher_callbacks_invoked': 0,
            'cipher_overrides': 0,
            'errors': 0,
        }
        
        self._lock = threading.RLock()
    
    def set_cipher_callback(self, callback: Callable[[str, str], Optional[TLSConfig]]):

        self.cipher_callback = callback
    
    def install(self):
        if self.installed:
            ctx.log.warn("[TLS-PATCHER] Already installed")
            return
        
        with self._lock:
            try:
                self._patch_stdlib_ssl()
                
                try:
                    import OpenSSL.SSL as SSL
                    self._patch_pyopenssl(SSL)
                except ImportError:
                    pass
                
                try:
                    self._patch_mitmproxy_internals()
                except Exception as e:
                    pass
                
                self.installed = True
                
            except Exception as e:
                ctx.log.error(f"[TLS-PATCHER] Installation failed: {e}")
                ctx.log.error(f"[TLS-PATCHER] Traceback: {traceback.format_exc()}")
                raise
    
    def _patch_stdlib_ssl(self):
        self._originals['SSLContext.__init__'] = ssl.SSLContext.__init__
        self._originals['SSLContext.set_ciphers'] = ssl.SSLContext.set_ciphers
        
        patcher_self = self 
        
        def patched_sslcontext_init(ctx_self, protocol=ssl.PROTOCOL_TLS):
            patcher_self.stats['contexts_created'] += 1
            
            result = patcher_self._originals['SSLContext.__init__'](ctx_self, protocol)
            
            try:
                tls_config = getattr(_thread_local, 'tls_config', None)
                if tls_config and tls_config.cipher_suites:
                    cipher_string = CipherMapper.iana_to_openssl(tls_config.cipher_suites)
                    if cipher_string:
                        ctx_self.set_ciphers(cipher_string)
                        patcher_self.stats['contexts_configured'] += 1
                        ctx.log.debug(f"[TLS-PATCHER] Auto-configured SSLContext: {cipher_string[:60]}...")
            except Exception as e:
                ctx.log.debug(f"[TLS-PATCHER] Could not auto-configure context: {e}")
            
            return result
        
        def patched_set_ciphers(ctx_self, ciphers):
            tls_config = getattr(_thread_local, 'tls_config', None)
            if tls_config and tls_config.cipher_suites:
                custom_cipher_string = CipherMapper.iana_to_openssl(tls_config.cipher_suites)
                if custom_cipher_string:
                    ctx.log.debug(f"[TLS-PATCHER] Overriding ciphers: {ciphers} -> {custom_cipher_string[:60]}...")
                    ciphers = custom_cipher_string
                    patcher_self.stats['cipher_overrides'] += 1
            
            return patcher_self._originals['SSLContext.set_ciphers'](ctx_self, ciphers)
        
        ssl.SSLContext.__init__ = patched_sslcontext_init
        ssl.SSLContext.set_ciphers = patched_set_ciphers
    
    def _patch_pyopenssl(self, SSL):
        self._originals['SSL.Context.__init__'] = SSL.Context.__init__
        self._originals['SSL.Context.set_cipher_list'] = SSL.Context.set_cipher_list
        
        patcher_self = self
        
        def patched_context_init(ctx_self, method):
            patcher_self.stats['contexts_created'] += 1
            
            result = patcher_self._originals['SSL.Context.__init__'](ctx_self, method)
            
            try:
                tls_config = getattr(_thread_local, 'tls_config', None)
                if tls_config and tls_config.cipher_suites:
                    cipher_string = CipherMapper.iana_to_openssl(tls_config.cipher_suites)
                    if cipher_string:
                        ctx_self.set_cipher_list(cipher_string.encode('utf-8'))
                        patcher_self.stats['contexts_configured'] += 1
                        ctx.log.debug(f"[TLS-PATCHER] Auto-configured pyOpenSSL Context: {cipher_string[:60]}...")
            except Exception as e:
                ctx.log.debug(f"[TLS-PATCHER] Could not auto-configure pyOpenSSL context: {e}")
            
            return result
        
        def patched_set_cipher_list(ctx_self, cipher_list):
            tls_config = getattr(_thread_local, 'tls_config', None)
            if tls_config and tls_config.cipher_suites:
                custom_cipher_string = CipherMapper.iana_to_openssl(tls_config.cipher_suites)
                if custom_cipher_string:
                    ctx.log.debug(f"[TLS-PATCHER] Overriding pyOpenSSL ciphers: {cipher_list} -> {custom_cipher_string[:60]}...")
                    cipher_list = custom_cipher_string.encode('utf-8')
                    patcher_self.stats['cipher_overrides'] += 1
            
            return patcher_self._originals['SSL.Context.set_cipher_list'](ctx_self, cipher_list)
        
        SSL.Context.__init__ = patched_context_init
        SSL.Context.set_cipher_list = patched_set_cipher_list
    
    def _patch_mitmproxy_internals(self):
        try:
            from mitmproxy.net import tls
            
            if hasattr(tls, 'create_client_context'):
                self._originals['tls.create_client_context'] = tls.create_client_context
                
                patcher_self = self
                
                def patched_create_client_context(*args, **kwargs):
                    ssl_ctx = patcher_self._originals['tls.create_client_context'](*args, **kwargs)
                    
                    tls_config = getattr(_thread_local, 'tls_config', None)
                    if tls_config and tls_config.cipher_suites:
                        cipher_string = CipherMapper.iana_to_openssl(tls_config.cipher_suites)
                        if cipher_string:
                            try:
                                ssl_ctx.set_ciphers(cipher_string)
                                ctx.log.debug(f"[TLS-PATCHER] Configured mitmproxy client context: {cipher_string[:60]}...")
                            except Exception as e:
                                ctx.log.warn(f"[TLS-PATCHER] Failed to set ciphers on mitmproxy context: {e}")
                    
                    return ssl_ctx
                
                tls.create_client_context = patched_create_client_context
                
        except ImportError:
            pass
    
    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)
    
    def set_connection_config(self, hostname: str, sni: str):
        try:
            self.stats['cipher_callbacks_invoked'] += 1
            
            tls_config = None
            if self.cipher_callback:
                tls_config = self.cipher_callback(hostname, sni)
            
            if tls_config:
                tls_config.hostname = hostname
                _thread_local.tls_config = tls_config
                ctx.log.debug(f"[TLS-PATCHER] Set config for {hostname}: {len(tls_config.cipher_suites)} ciphers")
            else:
                if hasattr(_thread_local, 'tls_config'):
                    delattr(_thread_local, 'tls_config')
                    
        except Exception as e:
            self.stats['errors'] += 1
            ctx.log.error(f"[TLS-PATCHER] Error setting connection config: {e}")
            ctx.log.error(f"[TLS-PATCHER] Traceback: {traceback.format_exc()}")
    
    def clear_connection_config(self):
        if hasattr(_thread_local, 'tls_config'):
            delattr(_thread_local, 'tls_config')


_global_patcher: Optional[TLSMitmPatcher] = None


def get_patcher() -> TLSMitmPatcher:
    global _global_patcher
    if _global_patcher is None:
        _global_patcher = TLSMitmPatcher()
    return _global_patcher


def install_tls_patches():
    patcher = get_patcher()
    if not patcher.installed:
        patcher.install()
    return patcher
