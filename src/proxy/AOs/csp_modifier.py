""" CSP Modifier Addon for mitmproxy

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
This addon modifies CSP response headers to allow proxy-injected JavaScript
while maintaining maximum security protections.

SECURITY-FIRST APPROACH:
1. Generate a unique nonce for each response
2. Inject nonce into CSP script-src (ONLY the nonce, not unsafe-inline)
3. Store nonce in flow.metadata for js_injector to use
4. Preserve ALL other CSP protections (Trusted Types, frame restrictions, etc.)
5. Only modify CSP on sites that are actually fingerprinting (optional allowlist)

This ensures injected scripts pass CSP validation WITHOUT weakening XSS protection.

Usage:
    mitmproxy -s mitm/csp_modifier.py

Configuration:
    Set MODIFY_ALL_SITES = False to only modify known fingerprinting sites
    Add domains to FINGERPRINTING_SITES list
"""
from mitmproxy import ctx
import re
import base64
import os


# Configuration
MODIFY_ALL_SITES = True  # Set to False for allowlist-only mode
VERBOSE_LOGGING = True  # Set to True for detailed debug logs

# Sites known to use aggressive fingerprinting
FINGERPRINTING_SITES = [
    'google.com',
    'facebook.com',
    'amazon.com',
    'reddit.com',
    'twitter.com',
    'linkedin.com',
    'instagram.com',
    'tiktok.com',
    'youtube.com',
]

# Sites that should NEVER have CSP modified
PROTECTED_SITES = [
    'bankofamerica.com',
    'chase.com',
    'wellsfargo.com',
    'paypal.com',
    'irs.gov',
    'usa.gov',
    # Add your sensitive sites here
]


class CSPModifier:
    def __init__(self):
        self.enabled = True
        self.stats = {
            'total_responses': 0,
            'csp_modified': 0,
            'csp_skipped': 0,
            'nonces_generated': 0,
            'nonces_extracted': 0,
        }
    
    def responseheaders(self, flow):
        """Early hook: Extract/generate nonce and store in flow.metadata.
        
        This runs BEFORE response body is available, allowing us to extract
        nonces early so JSInjector can use them when injecting scripts.
        """
        # DEBUG: Track hook execution order
        ctx.log.error(f"[CSP DEBUG] ===== responseheaders() CALLED for {flow.request.host} =====")
        
        if not self.enabled:
            return
        
        try:
            if self._is_protected_site(flow.request.host):
                if VERBOSE_LOGGING:
                    ctx.log.info(f"[CSP] Skipping protected site: {flow.request.host}")
                self.stats['csp_skipped'] += 1
                return
            
            if not MODIFY_ALL_SITES and not self._should_modify_site(flow.request.host):
                if VERBOSE_LOGGING:
                    ctx.log.debug(f"[CSP] Site not in allowlist: {flow.request.host}")
                self.stats['csp_skipped'] += 1
                return

            csp_headers = self._get_csp_headers(flow)
            if not csp_headers:
                nonce = self._generate_nonce()
                flow.metadata['csp_nonce'] = nonce
                self.stats['nonces_generated'] += 1
                ctx.log.info(f"[CSP] No CSP headers, generated nonce: {nonce[:12]}...")
                return

            nonce = None
            for header_name, original_csp in csp_headers:
                extracted_nonces = self._extract_nonces(original_csp)
                ctx.log.info(f"[CSP] Extracting nonces from {header_name}: found {len(extracted_nonces)} nonce(s)")
                if extracted_nonces:
                    nonce = extracted_nonces[0]
                    self.stats['nonces_extracted'] += 1
                    ctx.log.info(f"[CSP] Extracted nonce: '{nonce}'")
                    break
            
            if not nonce:
                nonce = self._generate_nonce()
                self.stats['nonces_generated'] += 1
                ctx.log.info(f"[CSP] Generated nonce: '{nonce}'")
            
            flow.metadata['csp_nonce'] = nonce
            # DEBUG: Critical logging to trace nonce flow
            ctx.log.error(f"[CSP DEBUG] Set nonce='{nonce}' (len:{len(nonce)}) for {flow.request.host}")
            ctx.log.error(f"[CSP DEBUG] flow.metadata keys after set: {list(flow.metadata.keys())}")
            
        except Exception as e:
            ctx.log.error(f"[CSP] Error in responseheaders: {e}")
        
    def response(self, flow):
        """Late hook: Modify CSP headers with nonce + script hashes.
        
        This runs AFTER JSInjector has computed script hashes and stored them
        in flow.metadata['script_hashes'], allowing us to add them to CSP.
        
        CRITICAL: Must use lower priority than JSInjector to run after it!
        """
        # DEBUG: Track hook execution order
        ctx.log.error(f"[CSP DEBUG] ===== response() CALLED for {flow.request.host} =====")
        
        if not self.enabled:
            return
        
        self.stats['total_responses'] += 1
        
        try:
            if self._is_protected_site(flow.request.host):
                return
            
            if not MODIFY_ALL_SITES and not self._should_modify_site(flow.request.host):
                return

            csp_headers = self._get_csp_headers(flow)
            if not csp_headers:
                return  # No CSP to modify
            
            nonce = flow.metadata.get('csp_nonce')
            # DEBUG: Critical logging to trace nonce flow
            ctx.log.error(f"[CSP DEBUG] response() reading nonce='{nonce}' from metadata")
            ctx.log.error(f"[CSP DEBUG] All metadata keys in response(): {list(flow.metadata.keys())}")
            if not nonce:
                ctx.log.error(f"[CSP DEBUG] PROBLEM: No nonce found in flow.metadata for {flow.request.host}!")
                return
            
            # Get script hashes from JSInjector
            script_hashes = flow.metadata.get('script_hashes', [])
            if script_hashes:
                ctx.log.info(f"[CSP] Found {len(script_hashes)} script hashes from JSInjector")
                ctx.log.error(f"[CSP DEBUG] ✅ JSInjector ran BEFORE CSPModifier - hook order correct!")
            else:
                ctx.log.error("[CSP DEBUG] ❌ WARNING: No script hashes! JSInjector may have run AFTER CSPModifier!")
                ctx.log.warn("[CSP] No script hashes found - will only add nonce to CSP")
       
            modified = False
            for header_name, original_csp in csp_headers:
                # DEBUG: Log full original CSP
                ctx.log.error(f"[CSP DEBUG] Original CSP length: {len(original_csp)} chars")
                ctx.log.error(f"[CSP DEBUG] Original CSP: {original_csp[:500]}...")
                
                new_csp = self._modify_csp_secure(original_csp, nonce, script_hashes)
                
                # DEBUG: Log full modified CSP
                ctx.log.error(f"[CSP DEBUG] Modified CSP length: {len(new_csp)} chars")
                ctx.log.error(f"[CSP DEBUG] Modified CSP: {new_csp[:500]}...")
                
                if new_csp != original_csp:
                    flow.response.headers[header_name] = new_csp
                    modified = True
                    ctx.log.info(f"[CSP] Modified {header_name} for {flow.request.host}")
                    if VERBOSE_LOGGING:
                        ctx.log.debug(f"[CSP] Original: {original_csp[:100]}...")
                        ctx.log.debug(f"[CSP] Modified: {new_csp[:100]}...")
            
            if modified:
                self.stats['csp_modified'] += 1
                        
        except Exception as e:
            ctx.log.error(f"[CSP] Error processing {flow.request.host}: {e}")
            import traceback
            ctx.log.error(f"[CSP] Traceback: {traceback.format_exc()}")
    
    def _is_protected_site(self, host):
        host_lower = host.lower()
        return any(protected in host_lower for protected in PROTECTED_SITES)
    
    def _should_modify_site(self, host):
        host_lower = host.lower()
        return any(site in host_lower for site in FINGERPRINTING_SITES)
    
    def _get_csp_headers(self, flow):
        csp_headers = []
        
        if "Content-Security-Policy" in flow.response.headers:
            csp_headers.append(("Content-Security-Policy", 
                               flow.response.headers["Content-Security-Policy"]))
        
        if "Content-Security-Policy-Report-Only" in flow.response.headers:
            csp_headers.append(("Content-Security-Policy-Report-Only",
                               flow.response.headers["Content-Security-Policy-Report-Only"]))
        
        return csp_headers
    
    def _extract_nonces(self, csp_string):
        """Extract nonce values
        
        args:
            csp_string: The CSP header value
            
        Returns:
            List of nonce values (without the 'nonce-' prefix or quotes)
        """
        if not csp_string:
            return []
        
        # Find all nonce directives using regex
        # i.e. 'nonce-<base64-value>'
        nonce_pattern = r"'nonce-([A-Za-z0-9+/=_-]+)'"
        matches = re.findall(nonce_pattern, csp_string)
        
        return matches
    
    def _generate_nonce(self):
        """Generate a cryptographically random nonce value.
        
        Returns:
            Base64-encoded nonce value (without 'nonce-' prefix)
        """
        # Generate 16 bytes of random data (128 bits)
        random_bytes = os.urandom(16)
        # Base64 encode and strip padding
        nonce = base64.b64encode(random_bytes).decode('ascii').rstrip('=')
        return nonce
    
    def _modify_csp_secure(self, csp_string, nonce, script_hashes=None):
        """Modify CSP to allow our injected scripts while XSS protections remain.
        
        args:
            csp_string: The original CSP header value
            nonce: The nonce to inject (without 'nonce-' prefix)
            script_hashes: List of SHA-256 hashes for our scripts
            
        Returns:
            Modified CSP string with nonce and hashes added to script directives
        """
        if not csp_string or not csp_string.strip():
            return csp_string
        
        if script_hashes is None:
            script_hashes = []
        
        policies = [p.strip() for p in csp_string.split(',') if p.strip()]
        
        # Check if ANY policy has a script-src directive (across all comma-separated policies)
        has_any_script_src = any(
            any(d.strip().lower().startswith(('script-src', 'script-src-elem')) 
                for d in policy.split(';') if d.strip())
            for policy in policies
        )
        
        modified_policies = []
        
        for policy in policies:
            modified_policy = self._modify_single_policy(policy, nonce, script_hashes, 
                                                         create_fallback=not has_any_script_src)
            modified_policies.append(modified_policy)
        
        return ', '.join(modified_policies)
    
    def _modify_single_policy(self, policy, nonce, script_hashes=None, create_fallback=True):
        """Modify CSP to include nonce and script hashes.
        
        args:
            policy: A single CSP policy string
            nonce: The nonce to inject
            script_hashes: List of SHA-256 hashes for our scripts
            create_fallback: Whether to create a fallback script-src if none exists
            
        Returns:
            Modified policy string
        """
        if script_hashes is None:
            script_hashes = []
        
        directives = []
        script_src_modified = False
        script_src_elem_modified = False
        
        for directive in policy.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            
            parts = directive.split()
            if not parts:
                continue
            
            directive_name = parts[0].lower()
            directive_values = parts[1:] if len(parts) > 1 else []
            
            if directive_name in ['script-src', 'script-src-elem']:
                nonce_value = f"'nonce-{nonce}'"
                
                # Add nonce if not already present
                if nonce_value not in directive_values:
                    directive_values.insert(0, nonce_value)
                    if VERBOSE_LOGGING:
                        ctx.log.debug(f"[CSP] Added nonce to {directive_name}")
                
                # Add script hashes if not already present
                for hash_value in script_hashes:
                    hash_directive = f"'sha256-{hash_value}'"
                    if hash_directive not in directive_values:
                        directive_values.append(hash_directive)
                        if VERBOSE_LOGGING:
                            ctx.log.debug(f"[CSP] Added hash {hash_value[:16]}... to {directive_name}")
                
                if directive_name == 'script-src':
                    script_src_modified = True
                elif directive_name == 'script-src-elem':
                    script_src_elem_modified = True
                
                directives.append(f"{directive_name} {' '.join(directive_values)}")
            else:
                # Keep all other directives unchanged
                directives.append(directive)
        
        if not script_src_modified and create_fallback:
            nonce_value = f"'nonce-{nonce}'"
            hash_values = [f"'sha256-{h}'" for h in script_hashes]
            all_values = [nonce_value] + hash_values + ["'self'"]
            directives.append(f"script-src {' '.join(all_values)}")
            if VERBOSE_LOGGING:
                ctx.log.debug(f"[CSP] Created script-src with nonce and {len(script_hashes)} hashes")
        
        return '; '.join(directives)
    
    def done(self):
        if self.stats['total_responses'] > 0:
            ctx.log.info("[CSP] Statistics:")
            ctx.log.info(f"Total responses: {self.stats['total_responses']}")
            ctx.log.info(f"CSP modified: {self.stats['csp_modified']}")
            ctx.log.info(f"CSP skipped: {self.stats['csp_skipped']}")
            ctx.log.info(f"Nonces generated: {self.stats['nonces_generated']}")
            ctx.log.info(f"Nonces extracted: {self.stats['nonces_extracted']}")


addons = [CSPModifier()]