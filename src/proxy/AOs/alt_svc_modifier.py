""" ALT-SVC Modifier Addon for mitmproxy

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

"""HTTP/3 and QUIC protocols will be downgraded to HTTP/2

This helps to avoid detection methods that rely on the presence of HTTP/3 or QUIC

"""


from mitmproxy import ctx, http
import re
from typing import Dict, List, Optional


class AltSvcModifier:
    """
    Modifies Alt-Svc headers to prevent port-based proxy detection
    """
    
    def __init__(self):
        self.enabled = True
        self.verbose = True
        self.debug_mode = False
        
        self.strategy = "normalize" # Options: "remove", "normalize", "redirect"
        
        # Port normalization
        self.port_mapping = {
            "443": "443",   # Keep HTTPS standard
            "80": "80",     # Keep HTTP standard
            "8080": "443",  # Proxy port -> HTTPS
            "8443": "443",  # Alt HTTPS -> HTTPS
            "3128": "443",  # Squid proxy -> HTTPS
        }
        
        if self.verbose:
            ctx.log.info(f"[ALT_SVC] Initialized with strategy: {self.strategy}")
            ctx.log.info(f"[ALT_SVC] Monitoring all hosts for Alt-Svc headers")
    
    def _parse_alt_svc(self, alt_svc_value: str) -> List[Dict[str, str]]:
        services = []
        
        """ Alt-Svc format: 
        protocol="host:port"; ma=seconds, protocol2="host2:port2"
        1. h3=":443"; ma=2592000,h3-29=":443"
        2. h2="alt.example.com:8080"; ma=60
        """
        
        if not alt_svc_value or alt_svc_value.lower() == "clear":
            return services
        
        # get individual service entries
        service_entries = [s.strip() for s in alt_svc_value.split(',')]
        
        for entry in service_entries:
            if not entry:
                continue
                
            service = {}

            if '=' in entry:
                parts = entry.split(';')
                protocol_part = parts[0].strip()
                
                if '=' in protocol_part:
                    protocol, authority = protocol_part.split('=', 1)
                    service['protocol'] = protocol.strip()
                    service['authority'] = authority.strip().strip('"')
                    
                    # Parse ma, persist, etc.
                    for param_part in parts[1:]:
                        if '=' in param_part:
                            key, value = param_part.split('=', 1)
                            service[key.strip()] = value.strip()
                    
                    services.append(service)
        
        return services
    
    def _reconstruct_alt_svc(self, services: List[Dict[str, str]]) -> str:
        # Reconstruct Alt-Svc header
        if not services:
            return ""
        
        service_strings = []
        
        for service in services:
            if 'protocol' not in service or 'authority' not in service:
                continue
            
            service_str = f'{service["protocol"]}="{service["authority"]}"'
            
            for key, value in service.items():
                if key not in ['protocol', 'authority']:
                    service_str += f'; {key}={value}'
            
            service_strings.append(service_str)
        
        return ', '.join(service_strings)
    
    def _normalize_ports(self, services: List[Dict[str, str]]) -> List[Dict[str, str]]:
        normalized_services = []
        
        for service in services:
            if 'authority' not in service:
                normalized_services.append(service)
                continue
            
            authority = service['authority']
            
            # could be ":443", "host:port", or just "host"
            if authority.startswith(':'):
                # i.e. ":port"
                port = authority[1:]
                if port in self.port_mapping:
                    service['authority'] = f":{self.port_mapping[port]}"
            elif ':' in authority:
                # i.e. "host:port"
                host, port = authority.rsplit(':', 1)
                if port in self.port_mapping:
                    service['authority'] = f"{host}:{self.port_mapping[port]}"
            
            normalized_services.append(service)
        
        return normalized_services
    
    def _filter_protocols(self, services: List[Dict[str, str]]) -> List[Dict[str, str]]:
        filtered_services = []
        
        safe_protocols = ['h2', 'http/1.1']
        
        risky_protocols = ['h3', 'h3-29', 'h3-27', 'quic']
        
        for service in services:
            protocol = service.get('protocol', '')
            
            if protocol in safe_protocols:
                filtered_services.append(service)
            elif protocol in risky_protocols:
                if self.strategy == "normalize":
                    service['protocol'] = 'h2'
                    filtered_services.append(service)
                elif self.strategy == "redirect":
                    if 'authority' in service:
                        if service['authority'].startswith(':'):
                            service['authority'] = ':443'
                        elif ':' in service['authority']:
                            host, _ = service['authority'].rsplit(':', 1)
                            service['authority'] = f"{host}:443"
                    filtered_services.append(service)
            else:
                filtered_services.append(service)
        
        return filtered_services
    
    def _modify_alt_svc_header(self, original_value: str, hostname: str) -> Optional[str]:
        try:
            services = self._parse_alt_svc(original_value)
            
            if not services:
                return original_value
            
            if self.debug_mode:
                ctx.log.debug(f"[ALT_SVC] Parsed {len(services)} services from {hostname}")
                for i, service in enumerate(services):
                    ctx.log.debug(f"[ALT_SVC] Service {i}: {service}")
            
            if self.strategy == "remove":
                return None
            
            elif self.strategy == "normalize":
                services = self._normalize_ports(services)
                services = self._filter_protocols(services)
                
            elif self.strategy == "redirect":
                for service in services:
                    if 'authority' in service:
                        if service['authority'].startswith(':'):
                            service['authority'] = ':443'
                        elif ':' in service['authority']:
                            host, _ = service['authority'].rsplit(':', 1)
                            service['authority'] = f"{host}:443"
            
            modified_value = self._reconstruct_alt_svc(services)
            
            if self.verbose and modified_value != original_value:
                ctx.log.info(f"[ALT_SVC] Modified header for {hostname}")
                ctx.log.info(f"[ALT_SVC] Original: {original_value}")
                ctx.log.info(f"[ALT_SVC] Modified: {modified_value}")

            return modified_value
            
        except Exception as e:
            ctx.log.error(f"[ALT_SVC] Error modifying Alt-Svc for {hostname}: {e}")
            return original_value
    
    def response(self, flow: http.HTTPFlow) -> None:
        if not self.enabled:
            return
        
        try:
            hostname = flow.request.host
            
            alt_svc_headers = []
            
            for header_name in ['Alt-Svc', 'alt-svc']:
                if header_name in flow.response.headers:
                    alt_svc_headers.append((header_name, flow.response.headers[header_name]))
            
            if not alt_svc_headers:
                return
            
            for header_name, original_value in alt_svc_headers:
                modified_value = self._modify_alt_svc_header(original_value, hostname)
                
                if modified_value is None:
                    del flow.response.headers[header_name]
                    if self.verbose:
                        ctx.log.info(f"[ALT_SVC] Removed {header_name} header for {hostname}")
                
                elif modified_value != original_value:
                    flow.response.headers[header_name] = modified_value
                
        except Exception as e:
            ctx.log.error(f"[ALT_SVC] Error processing response from {flow.request.host}: {e}")


addons = [AltSvcModifier()]