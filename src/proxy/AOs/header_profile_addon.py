""" Header Profile Addon for mitmproxy

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
from mitmproxy.http import Headers
import json       
import os         
import re         
import time       
from typing import Dict, List, Tuple, Optional, Any

DEFAULT_PROFILE = "firefox-windows"

PROFILE_ROTATION_INTERVAL = 300  

MAX_PROFILE_FILE_SIZE = 10 * 1024 * 1024

MAX_PROFILE_CACHE_SIZE = 1000

ProfileDict = Dict[str, Any]

CacheEntry = Tuple[str, float, Optional[str], Optional[str], Dict[str, Any]]

_PROFILE_CACHE: Dict[str, CacheEntry] = {}

_PROFILES: Dict[str, ProfileDict] = {}

_PROFILES_BY_HOST: Dict[str, str] = {}

_FALLBACK_PROFILE: ProfileDict = {
    "set": [],                
    "replace": [],            
    "remove": [],             
    "append": [],             
    "pass": [],               
    "replaceArbitrary": [],   
    "replaceDynamic": [],     
    "fingerprint": {}         
}

def headers_to_list(hdrs: Headers) -> List[Tuple[str, str]]:
    """
    Convert mitmproxy Headers object to Python list of tuples
    """
    try:

        headers = list(hdrs.items(multi=True))
    except TypeError:

        headers = list(hdrs.items())

    result = []
    for name, value in headers:

        if isinstance(name, bytes):
            name = name.decode('utf-8', errors='replace')
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        result.append((name, value))

    return result

def list_to_headers(lst: List[Tuple[str, str]]) -> Headers:
    """
    Convert Python list of tuples back to mitmproxy Headers object
    """
    converted_lst = []
    for name, value in lst:

        if not isinstance(name, (str, bytes)):
            ctx.log.warn(f"Invalid header name type: {type(name)}, skipping")
            continue
        if not isinstance(value, (str, bytes)):
            ctx.log.warn(f"Invalid header value type: {type(value)}, skipping")
            continue

        if isinstance(name, str):
            name = name.encode('utf-8')
        if isinstance(value, str):
            value = value.encode('utf-8')
        converted_lst.append((name, value))

    return Headers(converted_lst)

def sanitize_profile_path(base_dir: str, filename: str) -> Optional[str]:
    """
    Validate profile file path to prevent path traversal attacks
    """
    base_dir = os.path.abspath(base_dir)
    requested_path = os.path.abspath(os.path.join(base_dir, filename))

    if not requested_path.startswith(base_dir):
        ctx.log.error(f"Path traversal attempt detected: {filename}")
        return None

    if not requested_path.endswith('.json'):
        ctx.log.error(f"Invalid profile file extension: {filename}")
        return None

    return requested_path

def sanitize_json_content(content: str) -> str:
    """
    Strip comments and invalid characters from JSON before parsing
    """

    content = re.sub(r'//.*', '', content)

    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

    content = ''.join(ch for ch in content if ch >= ' ' or ch in ['\n', '\r', '\t'])

    content = re.sub(r',\s*([}\]])', r'\1', content)
    return content

def validate_profile_structure(profile: ProfileDict) -> bool:
    """Check profile structure."""
    if not isinstance(profile, dict):
        return False

    expected_sections = {
        "set": list,
        "replace": list,
        "remove": list,
        "append": list,
        "pass": list,
        "replaceArbitrary": list,
        "replaceDynamic": list,
        "fingerprint": dict
    }

    for section, expected_type in expected_sections.items():
        if section in profile and not isinstance(profile[section], expected_type):
            ctx.log.error(f"Profile section '{section}' has incorrect type: {type(profile[section])}")
            return False

    return True

def safe_regex_match(pattern: str, text: str) -> bool:
    """Match regex with error handling."""
    try:
        return re.fullmatch(pattern, text) is not None
    except re.error as e:
        ctx.log.warn(f"Invalid regex pattern '{pattern}': {e}")
        return False
    except Exception as e:
        ctx.log.error(f"Unexpected error in regex matching: {e}")
        return False

def load_profiles(path: Optional[str] = None) -> None:
    """Load profiles from JSON."""
    global _PROFILES, _PROFILES_BY_HOST

    if path is None:
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "profiles.json"))
    else:
        base_dir = os.path.dirname(path)
        filename = os.path.basename(path)
        path = sanitize_profile_path(base_dir, filename)
        if path is None:
            ctx.log.error("Invalid profile path provided")
            return

    _PROFILES = {}
    _PROFILES_BY_HOST = {}

    if not os.path.exists(path):
        ctx.log.error(f"profiles.json not found at {path}")
        return

    try:
        file_size = os.path.getsize(path)
        if file_size > MAX_PROFILE_FILE_SIZE:
            ctx.log.error(f"Profile file too large: {file_size} bytes (max: {MAX_PROFILE_FILE_SIZE})")
            return
    except OSError as e:
        ctx.log.error(f"Cannot access profile file: {e}")
        return

    try:

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        content = sanitize_json_content(content)

        ctx.log.debug("Attempting to parse profiles.json")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            line_num = e.lineno
            col_num = e.colno
            ctx.log.error(f"JSON decode error at line {line_num}, column {col_num}: {e.msg}")
            lines = content.splitlines()
            if line_num <= len(lines):
                problematic_line = lines[line_num - 1]
                ctx.log.error(f"Line {line_num}: {problematic_line}")
                ctx.log.error(f"{' ' * (col_num - 1)}^")
            raise

        if not isinstance(data, dict):
            ctx.log.error("profiles.json must be a JSON object")
            return

        profiles_data = data.get("profiles", {})
        if not isinstance(profiles_data, dict):
            ctx.log.error("'profiles' section must be a JSON object")
            return

        for profile_name, profile_data in profiles_data.items():
            if not isinstance(profile_name, str) or not profile_name.strip():
                ctx.log.warn(f"Invalid profile name: {profile_name}, skipping")
                continue

            if not isinstance(profile_data, dict):
                ctx.log.warn(f"Profile '{profile_name}' is not a valid object, skipping")
                continue

            for section in ["set", "replace", "remove", "append", "pass", "replaceArbitrary", "replaceDynamic"]:
                if section not in profile_data:
                    profile_data[section] = []

            if "fingerprint" not in profile_data:
                profile_data["fingerprint"] = {}

            if not validate_profile_structure(profile_data):
                ctx.log.warn(f"Profile '{profile_name}' has invalid structure, skipping")
                continue

            if profile_data["set"] and isinstance(profile_data["set"], list):
                if profile_data["set"] and not isinstance(profile_data["set"][0], (list, tuple)):
                    new_set = []
                    for i in range(0, len(profile_data["set"]), 2):
                        if i + 1 < len(profile_data["set"]):
                            new_set.append([profile_data["set"][i], profile_data["set"][i + 1]])
                        else:
                            new_set.append([profile_data["set"][i], ""])
                    profile_data["set"] = new_set

            _PROFILES[profile_name] = profile_data

        hosts_data = data.get("hosts", {})
        if not isinstance(hosts_data, dict):
            ctx.log.warn("'hosts' section is not a valid object, ignoring")
        else:
            for host_pattern, profile_name in hosts_data.items():
                if not isinstance(host_pattern, str) or not isinstance(profile_name, str):
                    ctx.log.warn(f"Invalid host mapping: {host_pattern} -> {profile_name}, skipping")
                    continue
                _PROFILES_BY_HOST[host_pattern] = profile_name

        ctx.log.info(f"Loaded {len(_PROFILES)} profiles from {path}: {list(_PROFILES.keys())}")

        if DEFAULT_PROFILE not in _PROFILES:
            ctx.log.error(f"Default profile '{DEFAULT_PROFILE}' not found in profiles.json!")
            ctx.log.error(f"Available profiles: {list(_PROFILES.keys())}")

    except Exception as e:
        ctx.log.error(f"Failed to load profiles.json: {e}")
        import traceback
        ctx.log.debug(f"Traceback: {traceback.format_exc()}")

def find_first_header_index(headers_list: List[Tuple[str, str]], name: str) -> Optional[int]:
    """
    Find the index of the first occurrence of a header (case-insensitive).
    """
    lname = name.lower()
    for i, (n, v) in enumerate(headers_list):
        if n.lower() == lname:
            return i
    return None

def extract_profile_metadata(profile_data: ProfileDict) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
    """
    Extract metadata from profile.
    """
    user_agent = None
    browser_profile = None

    replace_section = profile_data.get("replace", [])
    if isinstance(replace_section, list):
        for item in replace_section:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                name, value = item[0], item[1]
                if isinstance(name, str) and name.lower() == "user-agent":
                    user_agent = str(value)
                    break

    if not user_agent:
        set_section = profile_data.get("set", [])
        if isinstance(set_section, list):
            for item in set_section:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    name, value = item[0], item[1]
                    if isinstance(name, str) and name.lower() == "user-agent":
                        user_agent = str(value)
                        break

    if user_agent:
        ua_lower = user_agent.lower()
        if "firefox" in ua_lower:
            browser_profile = "firefox-windows"
        elif "edg" in ua_lower:
            browser_profile = "edge-windows"
        elif "chrome" in ua_lower or "chromium" in ua_lower:
            browser_profile = "chrome-windows"
        elif "safari" in ua_lower and "mobile" in ua_lower:
            browser_profile = "mobile-safari"
        elif "safari" in ua_lower:
            browser_profile = "safari-macos"

    fingerprint_config = profile_data.get("fingerprint", {})
    if not isinstance(fingerprint_config, dict):
        fingerprint_config = {}

    return user_agent, browser_profile, fingerprint_config

def select_profile(request_line: str, headers_list: List[Tuple[str, str]], flow) -> Tuple[str, Optional[str], Optional[str], Dict[str, Any]]:
    """
    Pick profile for request.
    """
    global _PROFILE_CACHE

    try:
        if flow.client_conn.peername:
            client_ip = flow.client_conn.peername[0]

            if not isinstance(client_ip, str) or not client_ip:
                client_ip = "unknown"
        else:
            client_ip = "unknown"
    except Exception as e:
        ctx.log.debug(f"Could not extract client IP: {e}")
        client_ip = "unknown"

    current_time = time.time()

    if len(_PROFILE_CACHE) > MAX_PROFILE_CACHE_SIZE:
        ctx.log.info(f"Profile cache exceeded {MAX_PROFILE_CACHE_SIZE} entries, cleaning old entries")
        cutoff_time = current_time - PROFILE_ROTATION_INTERVAL
        _PROFILE_CACHE = {
            ip: entry for ip, entry in _PROFILE_CACHE.items()
            if entry[1] > cutoff_time
        }

    if client_ip in _PROFILE_CACHE:
        cached_profile, cached_time, cached_ua, cached_browser, cached_fingerprint = _PROFILE_CACHE[client_ip]
        age = current_time - cached_time

        if age < PROFILE_ROTATION_INTERVAL:
            ctx.log.debug(f"Using cached profile '{cached_profile}' for {client_ip} (age: {int(age)}s)")
            return cached_profile, cached_ua, cached_browser, cached_fingerprint
        else:
            ctx.log.info(f"Profile cache expired for {client_ip} (age: {int(age)}s), selecting new profile")

    idx = find_first_header_index(headers_list, "X-Proxy-Profile")
    if idx is not None:
        _, val = headers_list.pop(idx)
        profile_name = val.strip()

        if profile_name and profile_name in _PROFILES:
            profile_data = _PROFILES[profile_name]
            user_agent, browser_profile, fingerprint_config = extract_profile_metadata(profile_data)
            _PROFILE_CACHE[client_ip] = (profile_name, current_time, user_agent, browser_profile, fingerprint_config)
            ctx.log.info(f"Selected explicit profile '{profile_name}' for {client_ip}")
            return profile_name, user_agent, browser_profile, fingerprint_config
        else:
            ctx.log.warn(f"Requested profile '{profile_name}' not found. Using {DEFAULT_PROFILE} instead.")
            profile_name = DEFAULT_PROFILE
            profile_data = _PROFILES.get(profile_name, _FALLBACK_PROFILE)
            user_agent, browser_profile, fingerprint_config = extract_profile_metadata(profile_data)
            _PROFILE_CACHE[client_ip] = (profile_name, current_time, user_agent, browser_profile, fingerprint_config)
            return profile_name, user_agent, browser_profile, fingerprint_config

    host_idx = find_first_header_index(headers_list, "Host")
    if host_idx is not None:
        host_val = headers_list[host_idx][1]

        if ':' in host_val:
            host_val = host_val.split(":")[0]
        host_val = host_val.strip()

        if not host_val or len(host_val) > 255:
            ctx.log.warn(f"Invalid hostname: {host_val}")
        else:
            if host_val in _PROFILES_BY_HOST:
                profile_name = _PROFILES_BY_HOST[host_val]
                if profile_name in _PROFILES:
                    profile_data = _PROFILES[profile_name]
                    user_agent, browser_profile, fingerprint_config = extract_profile_metadata(profile_data)
                    _PROFILE_CACHE[client_ip] = (profile_name, current_time, user_agent, browser_profile, fingerprint_config)
                    ctx.log.info(f"Selected host-mapped profile '{profile_name}' for {host_val} ({client_ip})")
                    return profile_name, user_agent, browser_profile, fingerprint_config

            for pattern, profile_name in _PROFILES_BY_HOST.items():
                if safe_regex_match(pattern, host_val):
                    if profile_name in _PROFILES:
                        profile_data = _PROFILES[profile_name]
                        user_agent, browser_profile, fingerprint_config = extract_profile_metadata(profile_data)
                        _PROFILE_CACHE[client_ip] = (profile_name, current_time, user_agent, browser_profile, fingerprint_config)
                        ctx.log.info(f"Selected regex-mapped profile '{profile_name}' for {host_val} ({client_ip})")
                        return profile_name, user_agent, browser_profile, fingerprint_config

    profile_name = DEFAULT_PROFILE
    profile_data = _PROFILES.get(profile_name, _FALLBACK_PROFILE)
    user_agent, browser_profile, fingerprint_config = extract_profile_metadata(profile_data)
    _PROFILE_CACHE[client_ip] = (profile_name, current_time, user_agent, browser_profile, fingerprint_config)
    ctx.log.info(f"Selected default profile '{profile_name}' for {client_ip}")
    return profile_name, user_agent, browser_profile, fingerprint_config

def unescape_value(value: str) -> str:
    """Unescape header values."""
    if isinstance(value, str):
        value = value.replace('\\*', '*')
    return value

def detect_content_type(path: str, accept_header: str) -> Optional[str]:
    """Detect content type from path and Accept header."""
    path_lower = path.lower()
    accept_lower = accept_header.lower()

    if path_lower.endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico')):
        return "image"
    elif path_lower.endswith('.css'):
        return "css"
    elif path_lower.endswith('.json') or 'json' in accept_lower:
        return "json"
    elif path_lower.endswith('.js'):
        return "javascript"
    elif path_lower.endswith(('.woff', '.woff2', '.ttf', '.eot')):
        return "font"
    elif path_lower.endswith('.xml'):
        return "xml"

    if accept_header == '*/*' and not path_lower.endswith(('.html', '.htm')):
        return "xhr"
    elif 'text/html' not in accept_lower and 'application/xhtml' not in accept_lower:
        return "xhr"

    return None

def apply_profile(headers_list: List[Tuple[str, str]], profile_name: str, flow) -> Optional[str]:
    """Apply profile to headers."""
    profile = _PROFILES.get(profile_name, _FALLBACK_PROFILE)
    user_agent = None

    try:
        removes = {n.lower() for n in profile.get("remove", []) if isinstance(n, str)}
        if removes:
            headers_list[:] = [(n, v) for (n, v) in headers_list if n.lower() not in removes]

        for item in profile.get("replace", []):
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue

            name, newval = item[0], item[1]
            if not isinstance(name, str):
                continue

            newval = unescape_value(str(newval))

            idx = find_first_header_index(headers_list, name)
            if idx is not None:
                orig_name, _ = headers_list[idx]
                headers_list[idx] = (orig_name, newval)

            if name.lower() == "user-agent":
                user_agent = newval

        for item in profile.get("replaceArbitrary", []):
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue

            name, newval = item[0], item[1]
            if not isinstance(name, str):
                continue

            newval = unescape_value(str(newval))

            idx = find_first_header_index(headers_list, name)
            if idx is not None:
                orig_name, _ = headers_list[idx]
                headers_list[idx] = (orig_name, newval)

        for item in profile.get("replaceDynamic", []):
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue

            name, pattern_map = item[0], item[1]
            if not isinstance(name, str) or not isinstance(pattern_map, dict):
                continue

            idx = find_first_header_index(headers_list, name)
            if idx is not None:
                orig_name, orig_val = headers_list[idx]
                content_type = detect_content_type(flow.request.path, orig_val)

                if content_type == "xhr":
                    new_val = orig_val
                elif content_type and content_type in pattern_map:
                    new_val = str(pattern_map[content_type])
                else:
                    if 'text/html' in orig_val.lower() or orig_val == '*/*':
                        new_val = str(pattern_map.get("default", orig_val))
                    else:
                        new_val = orig_val

                new_val = unescape_value(new_val)

                if new_val != orig_val:
                    headers_list[idx] = (orig_name, new_val)

        for item in profile.get("set", []):
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue

            name, val = item[0], item[1]
            if not isinstance(name, str):
                continue

            val = unescape_value(str(val))

            if find_first_header_index(headers_list, name) is None:
                headers_list.append((name, val))

        for item in profile.get("append", []):
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue

            name, val = item[0], item[1]
            if not isinstance(name, str):
                continue

            val = unescape_value(str(val))
            headers_list.append((name, val))

    except Exception as e:
        ctx.log.error(f"Error applying profile '{profile_name}': {e}")
        import traceback
        ctx.log.debug(f"Traceback: {traceback.format_exc()}")

    return user_agent

class HeaderProfileAddon:

    def __init__(self):

        load_profiles()

        if not _PROFILES:
            ctx.log.error("No profiles loaded! Header modifications will be limited.")
        elif DEFAULT_PROFILE not in _PROFILES:
            ctx.log.error(f"Default profile '{DEFAULT_PROFILE}' not found!")
            ctx.log.error(f"Available profiles: {list(_PROFILES.keys())}")
        else:
            ctx.log.info(f"Header Profile Addon initialized with default: {DEFAULT_PROFILE}")
            ctx.log.info(f"Loaded {len(_PROFILES)} profiles: {list(_PROFILES.keys())}")

    def request(self, flow):
        ctx.log.error(f"[HEADER_PROFILE DEBUG] request() CALLED for {flow.request.host}")

        try:
            
            headers_list = headers_to_list(flow.request.headers)

            accept_idx = find_first_header_index(headers_list, "Accept")
            original_accept = headers_list[accept_idx][1] if accept_idx is not None else "N/A"

            profile_name, cached_user_agent, cached_browser_profile, fingerprint_config = select_profile(
                flow.request.path + " " + flow.request.http_version,
                headers_list,
                flow
            )

            ctx.log.info(f"Applying profile '{profile_name}' for {flow.request.host}{flow.request.path}")

            user_agent = apply_profile(headers_list, profile_name, flow)

            flow.metadata['profile_name'] = profile_name
            flow.metadata['browser_profile'] = cached_browser_profile or profile_name
            flow.metadata['user_agent'] = user_agent or cached_user_agent
            flow.metadata['fingerprint_config'] = fingerprint_config

            ctx.log.error(f"[HEADER_PROFILE DEBUG] Stored in flow.metadata:")
            ctx.log.error(f" - profile_name: {profile_name}")
            ctx.log.error(f" - browser_profile: {cached_browser_profile or profile_name}")
            ctx.log.error(f" - user_agent: {(user_agent or cached_user_agent)[:60] if user_agent or cached_user_agent else 'None'}...")
            ctx.log.error(f" - fingerprint_config: {len(fingerprint_config)} keys")

            if user_agent:
                ctx.log.debug(f"[HEADER_PROFILE] Stored UA: {user_agent[:60]}...")
            if fingerprint_config:
                ctx.log.debug(f"[HEADER_PROFILE] Stored fingerprint config with {len(fingerprint_config)} keys")

            new_accept_idx = find_first_header_index(headers_list, "Accept")
            new_accept = headers_list[new_accept_idx][1] if new_accept_idx is not None else "N/A"

            if original_accept != new_accept:
                ctx.log.info(f"Accept header modified for {flow.request.host}{flow.request.path}")
                ctx.log.debug(f" Original: {original_accept}")
                ctx.log.debug(f" New: {new_accept}")

            flow.request.headers = list_to_headers(headers_list)

        except Exception as e:
            ctx.log.error(f"HeaderProfileAddon error: {e}")
            import traceback
            ctx.log.debug(f"Traceback: {traceback.format_exc()}")

addons = [HeaderProfileAddon()]