#!/usr/bin/env python3
"""
Network Scanner for SSLMon
Discovers SSL-enabled hosts on local networks
"""

import socket
import ipaddress
import time
import dns.resolver
import dns.zone
import dns.query
from typing import List, Dict
import cert_checker

def get_local_networks() -> List[str]:
    """Detect local networks this server is connected to."""
    import netifaces
    networks = []
    
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for addr_info in addrs[netifaces.AF_INET]:
                ip = addr_info.get('addr')
                netmask = addr_info.get('netmask')
                
                # Skip loopback
                if ip.startswith('127.'):
                    continue
                
                if ip and netmask:
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        networks.append(str(network))
                    except:
                        pass
    
    return list(set(networks))  # Remove duplicates


def parse_ip_range(range_str: str) -> List[str]:
    """Parse IP range string into list of IPs."""
    ips = []
    
    # Handle CIDR notation (192.168.1.0/24)
    if '/' in range_str:
        try:
            network = ipaddress.IPv4Network(range_str, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except Exception as e:
            raise ValueError(f"Invalid CIDR notation: {e}")
    
    # Handle range notation (192.168.1.1-192.168.1.254)
    elif '-' in range_str:
        try:
            start_ip, end_ip = range_str.split('-')
            start = ipaddress.IPv4Address(start_ip.strip())
            end = ipaddress.IPv4Address(end_ip.strip())
            
            current = int(start)
            end_int = int(end)
            
            while current <= end_int:
                ips.append(str(ipaddress.IPv4Address(current)))
                current += 1
        except Exception as e:
            raise ValueError(f"Invalid IP range: {e}")
    
    # Single IP
    else:
        try:
            ipaddress.IPv4Address(range_str.strip())
            ips = [range_str.strip()]
        except:
            raise ValueError(f"Invalid IP address: {range_str}")
    
    return ips


def scan_host(ip: str, port: int = 443, timeout: int = 3) -> Dict:
    """Scan a single host for SSL certificate."""
    result = {
        'ip': ip,
        'domain': ip,
        'has_ssl': False
    }
    
    try:
        # Try reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result['domain'] = hostname
        except:
            pass
        
        # Try SSL connection
        cert_result = cert_checker.check_certificate(result['domain'], port=port, timeout=timeout)
        
        if cert_result.get('ok'):
            result['has_ssl'] = True
            result['expires'] = cert_result.get('expires')
            result['issued'] = cert_result.get('issued')
            result['days_remaining'] = cert_result.get('days_remaining')
            result['issuer'] = cert_result.get('issuer')
            result['subject'] = cert_result.get('subject')
            result['is_self_signed'] = cert_result.get('is_self_signed')
            result['tls_version'] = cert_result.get('tls_version')
    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def scan_network(ips: List[str], delay: float = 0.2) -> List[Dict]:
    """Scan multiple IPs for SSL certificates with rate limiting."""
    discovered = []
    
    for ip in ips:
        result = scan_host(ip)
        
        if result.get('has_ssl'):
            discovered.append(result)
        
        # Rate limiting (5 hosts/second by default)
        time.sleep(delay)
    
    return discovered


def query_dns_zone(dns_server: str, zone_name: str) -> List[str]:
    """Query DNS server for all hosts in a zone (if zone transfer allowed)."""
    hosts = []
    
    try:
        # Try zone transfer (AXFR) - usually restricted
        zone = dns.zone.from_xfr(dns.query.xfr(dns_server, zone_name))
        
        for name, node in zone.nodes.items():
            hostname = str(name)
            if hostname != '@':
                full_name = f"{hostname}.{zone_name}" if hostname else zone_name
                hosts.append(full_name)
    
    except Exception as e:
        # Zone transfer failed, try alternative method
        # Query common record types
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server] if not dns_server.replace('.', '').isalpha() else None
        
        # Try to enumerate some common hostnames
        common_names = [
            'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'webmail', 'remote',
            'vpn', 'gateway', 'fw', 'firewall', 'dc', 'dc1', 'dc2', 'ad',
            'server', 'server1', 'server2', 'web', 'db', 'sql', 'mysql',
            'exchange', 'owa', 'portal', 'intranet', 'sharepoint'
        ]
        
        for name in common_names:
            try:
                full_name = f"{name}.{zone_name}"
                answers = resolver.resolve(full_name, 'A')
                if answers:
                    hosts.append(full_name)
            except:
                pass
    
    return hosts
