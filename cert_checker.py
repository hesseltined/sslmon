#!/usr/bin/env python3
"""
SSL Certificate Checker Module

Connects to HTTPS endpoints, retrieves certificate details without chain validation,
and returns structured information including expiry dates, issuer, and self-signed status.

Author: Doug Hesseltine
Copyright: Technologist.services 2025
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID


DEFAULT_TIMEOUT = 10


def check_certificate(domain: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Connect to domain:port, retrieve remote TLS certificate without chain validation,
    parse core fields, and return a structured result.
    
    Args:
        domain: The hostname to check (e.g., 'example.com')
        port: The port to connect to (default: 443)
        timeout: Connection timeout in seconds (default: 10)
    
    Returns:
        Dictionary containing certificate details and status:
        - domain: The domain checked
        - port: The port used
        - issued: Certificate issue date (YYYY-MM-DD)
        - expires: Certificate expiry date (YYYY-MM-DD)
        - days_remaining: Days until expiration (negative if expired)
        - issuer: Certificate issuer (CA name)
        - subject: Certificate subject
        - is_self_signed: Boolean indicating if certificate is self-signed
        - tls_version: TLS version used for connection
        - checked_at: ISO timestamp of check
        - ok: Boolean indicating if check succeeded
        - error: Error message if check failed (None if ok=True)
        - error_type: Error category (dns, timeout, refused, ssl, network, unknown)
    
    Example:
        >>> result = check_certificate('google.com')
        >>> if result['ok']:
        ...     print(f"Expires: {result['expires']}, Days left: {result['days_remaining']}")
    """
    now = datetime.now(timezone.utc)
    result: Dict[str, Any] = {
        "domain": domain,
        "port": port,
        "issued": None,
        "expires": None,
        "days_remaining": None,
        "issuer": None,
        "subject": None,
        "is_self_signed": None,
        "tls_version": None,
        "checked_at": now.isoformat(),
        "ok": False,
        "error": None,
        "error_type": None,
    }

    try:
        # Create SSL context that doesn't validate certificate chain
        # This allows us to inspect expired, invalid, or self-signed certificates
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Connect and retrieve certificate
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            # Use server_hostname for SNI (Server Name Indication)
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["tls_version"] = ssock.version()
                cert_der = ssock.getpeercert(binary_form=True)

        # Parse certificate details
        parsed = _parse_x509(cert_der)
        result.update(parsed)
        result["ok"] = True
        return result

    except socket.gaierror as e:
        return _err(result, "dns", f"DNS resolution failed: {e}")
    except socket.timeout:
        return _err(result, "timeout", "Connection timeout reached")
    except ConnectionRefusedError as e:
        return _err(result, "refused", f"Connection refused: {e}")
    except ssl.SSLError as e:
        return _err(result, "ssl", f"SSL error: {e}")
    except OSError as e:
        # Covers various low-level connection issues on different platforms
        return _err(result, "network", f"Network error: {e}")
    except Exception as e:
        return _err(result, "unknown", f"{type(e).__name__}: {e}")


def _err(base: Dict[str, Any], error_type: str, message: str) -> Dict[str, Any]:
    """
    Mark result dictionary with error information.
    
    Args:
        base: The result dictionary to update
        error_type: Category of error (dns, timeout, refused, ssl, network, unknown)
        message: Human-readable error message
    
    Returns:
        Updated result dictionary with error details
    """
    base["ok"] = False
    base["error_type"] = error_type
    base["error"] = message
    return base


def _parse_x509(cert_der: bytes) -> Dict[str, Any]:
    """
    Parse X.509 certificate from DER format.
    
    Args:
        cert_der: Certificate in DER binary format
    
    Returns:
        Dictionary with parsed certificate fields:
        - issuer: Issuer common name or full DN
        - subject: Subject common name or full DN
        - is_self_signed: Boolean
        - issued: Issue date (YYYY-MM-DD)
        - expires: Expiry date (YYYY-MM-DD)
        - days_remaining: Days until expiration
    """
    cert = x509.load_der_x509_certificate(cert_der)

    issuer_cn = _get_cn(cert.issuer)
    subject_cn = _get_cn(cert.subject)

    issued_dt = cert.not_valid_before_utc
    expires_dt = cert.not_valid_after_utc

    # Calculate days remaining (can be negative if expired)
    now = datetime.now(timezone.utc)
    days_remaining = (expires_dt - now).days

    # Build result with fallback to full DN if CN not available
    return {
        "issuer": issuer_cn or cert.issuer.rfc4514_string(),
        "subject": subject_cn or cert.subject.rfc4514_string(),
        "is_self_signed": _is_self_signed(issuer_cn, subject_cn, cert),
        "issued": issued_dt.date().isoformat(),
        "expires": expires_dt.date().isoformat(),
        "days_remaining": days_remaining,
    }


def _get_cn(name: x509.Name) -> Optional[str]:
    """
    Extract Common Name (CN) from X.509 Name.
    
    Args:
        name: X.509 Name object (issuer or subject)
    
    Returns:
        Common Name string or None if not found
    """
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def _is_self_signed(issuer_cn: Optional[str], subject_cn: Optional[str], cert: x509.Certificate) -> bool:
    """
    Determine if certificate is self-signed.
    
    Checks both Common Name matching and full Name equality.
    
    Args:
        issuer_cn: Issuer common name
        subject_cn: Subject common name
        cert: X.509 certificate object
    
    Returns:
        True if certificate is self-signed, False otherwise
    """
    # Primary check: compare CNs
    if issuer_cn and subject_cn and issuer_cn == subject_cn:
        return True
    
    # Fallback: compare full distinguished names
    if cert.issuer == cert.subject:
        return True
    
    return False


if __name__ == "__main__":
    # Simple CLI for local testing:
    #   python cert_checker.py technologist.services google.com
    import sys
    import json
    
    domains = sys.argv[1:] or ["technologist.services", "google.com"]
    results = [check_certificate(d) for d in domains]
    print(json.dumps(results, indent=2))
