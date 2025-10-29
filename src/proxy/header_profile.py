""" Main mitmproxy Addon Caller

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

"""Loaded addons (EXECUTION ORDER):
1. HeaderProfileAddon - HTTP header manipulation and browser profile management
2. CSPModifier.responseheaders() - Extract/generate nonce (EARLY HOOK)
3. JSInjector.response() - Inject scripts with nonce, compute hashes **RUNS FIRST**
4. CSPModifier.response() - Add nonce + hashes to CSP (LATE HOOK) **RUNS LAST**
5. AltSvcModifier - Alt-Svc header normalization for proxy hiding
"""
# Usage: mitmproxy -s proxy/header_profile.py


from mitmproxy import ctx
from typing import List

addon_list: List = []

# Import HeaderProfile addon
try:
    from AOs.header_profile_addon import HeaderProfileAddon
    addon_list.append(HeaderProfileAddon())
    ctx.log.info("[ORCHESTRATOR] Loaded HeaderProfileAddon")
except ImportError as e:
    ctx.log.error(f"[ORCHESTRATOR] Failed to load HeaderProfileAddon: {e}")
except Exception as e:
    ctx.log.error(f"[ORCHESTRATOR] Unexpected error loading HeaderProfileAddon: {e}")

# Import JavaScript Injector addon - LOADS FIRST for response() hook
# This ensures it runs BEFORE CSPModifier.response()
# Reads nonce from flow.metadata['csp_nonce'] set by CSPModifier.responseheaders()
# Computes script hashes and stores in flow.metadata['script_hashes']
try:
    from AOs.js_injector import JSInjector
    addon_list.append(JSInjector())
    ctx.log.info("[ORCHESTRATOR] Loaded JSInjector (response() hook priority: FIRST)")
except ImportError as e:
    ctx.log.warn(f"[ORCHESTRATOR] JS injector not found: {e}")
except Exception as e:
    ctx.log.error(f"[ORCHESTRATOR] Unexpected error loading JSInjector: {e}")

# Import CSP Modifier addon - LOADS LAST for response() hook
# responseheaders() extracts/generates nonce EARLY (before JSInjector)
# response() adds hashes to CSP LATE (after JSInjector stores them)
try:
    from AOs.csp_modifier import CSPModifier
    addon_list.append(CSPModifier())
    ctx.log.info("[ORCHESTRATOR] Loaded CSPModifier (response() hook priority: LAST)")
except ImportError as e:
    ctx.log.warn(f"[ORCHESTRATOR] CSP modifier not found: {e}")
except Exception as e:
    ctx.log.error(f"[ORCHESTRATOR] Unexpected error loading CSPModifier: {e}")

# Import Alt-Svc Modifier addon
try:
    from AOs.alt_svc_modifier import AltSvcModifier
    addon_list.append(AltSvcModifier())
    ctx.log.info("[ORCHESTRATOR] Loaded AltSvcModifier")
except ImportError as e:
    ctx.log.warn(f"[ORCHESTRATOR] Alt-Svc modifier not found: {e}")
except Exception as e:
    ctx.log.error(f"[ORCHESTRATOR] Unexpected error loading AltSvcModifier: {e}")

addons = addon_list

ctx.log.info(f"[ORCHESTRATOR] Total addons loaded: {len(addons)}")
if len(addons) == 0:
    ctx.log.error("[ORCHESTRATOR] WARNING: No addons were successfully loaded!")
else:
    addon_names = [type(addon).__name__ for addon in addons]
    ctx.log.info(f"[ORCHESTRATOR] Active addons: {', '.join(addon_names)}")
