"""
CAC/PIV Identity Handler Module

This module provides utilities for handling DoD Common Access Card (CAC) and
Federal Personal Identity Verification (PIV) card authentication in Python
web applications.

WHAT IS CAC/PIV?
================
CAC (Common Access Card) - DoD smart card for identification and authentication
PIV (Personal Identity Verification) - Federal smart card standard (FIPS 201)

Both cards contain X.509 certificates used for:
- User authentication (instead of passwords)
- Digital signatures
- Encryption

HOW CAC/PIV AUTHENTICATION WORKS:
=================================
1. User inserts CAC/PIV card into reader
2. Browser/client performs TLS client certificate authentication
3. TLS terminates at reverse proxy (nginx, Apache, load balancer)
4. Proxy extracts certificate info, passes to application via headers
5. Application validates identity and creates session

WHY THIS MATTERS FOR ZERO TRUST:
================================
CAC/PIV provides strong identity verification:
- Something you HAVE (the physical card)
- Something you KNOW (the PIN)
- Cryptographically verifiable identity

This is much stronger than passwords alone and is required for many
federal systems, especially DoD (IL4+).

FEDERAL COMPLIANCE:
===================
- FIPS 201-3 (PIV Standard)
- NIST SP 800-73 (PIV Interfaces)
- NIST SP 800-76 (PIV Biometrics)
- NIST IA-2 (Multi-Factor Authentication)
- DoD Instruction 8520.02 (PKI and PKE)

ARCHITECTURE NOTE:
==================
This module handles the APPLICATION layer. TLS client certificate
verification happens at the INFRASTRUCTURE layer (reverse proxy).

Typical deployment:
    [Client + CAC] -> [Load Balancer/nginx] -> [Application]
                      ^                        ^
                      TLS termination          This module
                      Cert verification        Identity extraction
"""

import re
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class CertificateType(Enum):
    """
    Types of certificates found on CAC/PIV cards
    
    Each card contains multiple certificates for different purposes.
    For authentication, we use the PIV Authentication certificate.
    """
    PIV_AUTH = "piv_authentication"      # Primary authentication cert
    DIGITAL_SIGNATURE = "digital_signature"  # For signing documents
    KEY_MANAGEMENT = "key_management"    # For encryption
    CARD_AUTH = "card_authentication"    # For physical access


@dataclass
class CACIdentity:
    """
    Parsed CAC/PIV Identity Information
    
    This structure contains the identity information extracted from
    a CAC/PIV certificate's Distinguished Name (DN).
    
    DoD CAC DN Format:
        CN=LASTNAME.FIRSTNAME.MIDDLENAME.EDIPI
        Example: CN=SMITH.JOHN.WILLIAM.1234567890
    
    Fields:
        common_name: Full CN from certificate
        last_name: User's last name
        first_name: User's first name
        middle_name: User's middle name (may be empty)
        edipi: Electronic Data Interchange Personal Identifier (10-digit DoD ID)
        email: Email from certificate (if present)
        organization: Organization from cert (if present)
        issuer: Certificate issuer DN
        serial_number: Certificate serial number
        valid_from: Certificate validity start
        valid_to: Certificate validity end
        auth_method: Always "CAC" or "PIV"
    """
    common_name: str
    last_name: str
    first_name: str
    middle_name: Optional[str]
    edipi: str
    email: Optional[str]
    organization: Optional[str]
    issuer: Optional[str]
    serial_number: Optional[str]
    valid_from: Optional[datetime]
    valid_to: Optional[datetime]
    auth_method: str = "CAC"
    
    def get_display_name(self) -> str:
        """Return human-readable name"""
        if self.middle_name:
            return f"{self.first_name} {self.middle_name} {self.last_name}"
        return f"{self.first_name} {self.last_name}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "common_name": self.common_name,
            "last_name": self.last_name,
            "first_name": self.first_name,
            "middle_name": self.middle_name,
            "edipi": self.edipi,
            "email": self.email,
            "organization": self.organization,
            "auth_method": self.auth_method
        }


# =============================================================================
# CERTIFICATE PARSING
# =============================================================================

class CACPIVHandler:
    """
    CAC/PIV Certificate Handler
    
    This class extracts and validates identity information from CAC/PIV
    certificates. It works with certificate data passed from a TLS-terminating
    reverse proxy.
    
    IMPORTANT: This class does NOT perform cryptographic certificate validation.
    That is done by the reverse proxy during TLS handshake. This class only
    parses the already-validated certificate information.
    
    Usage:
        handler = CACPIVHandler()
        identity = handler.extract_identity_from_headers(request.headers)
        if identity:
            # User authenticated via CAC/PIV
            user_id = identity.edipi
    """
    
    # Common header names used by reverse proxies
    # Your proxy may use different names - configure accordingly
    HEADER_CLIENT_DN = 'X-SSL-Client-DN'           # Certificate subject DN
    HEADER_CLIENT_CERT = 'X-SSL-Client-Cert'       # Full certificate (PEM)
    HEADER_CLIENT_VERIFY = 'X-SSL-Client-Verify'   # Verification status
    HEADER_CLIENT_ISSUER = 'X-SSL-Client-Issuer'   # Issuer DN
    HEADER_CLIENT_SERIAL = 'X-SSL-Client-Serial'   # Certificate serial
    
    # Regex for parsing DoD CAC Common Name
    # Format: LASTNAME.FIRSTNAME.MIDDLENAME.EDIPI or LASTNAME.FIRSTNAME.EDIPI
    CAC_CN_PATTERN = re.compile(
        r'^(?P<last>[A-Z\-\']+)\.'
        r'(?P<first>[A-Z\-\']+)\.'
        r'(?:(?P<middle>[A-Z\-\']+)\.)?'
        r'(?P<edipi>\d{10})$',
        re.IGNORECASE
    )
    
    # Alternative pattern for email-based certificates
    EMAIL_PATTERN = re.compile(r'emailAddress=([^,]+)', re.IGNORECASE)
    
    def __init__(self, trusted_issuers: Optional[list] = None):
        """
        Initialize handler with optional list of trusted issuers
        
        Args:
            trusted_issuers: List of trusted issuer DN patterns (optional)
                             If None, all issuers are accepted (proxy does validation)
        """
        self.trusted_issuers = trusted_issuers or []
    
    def extract_identity_from_headers(self, headers: Dict[str, str]) -> Optional[CACIdentity]:
        """
        Extract CAC/PIV identity from reverse proxy headers
        
        ZERO TRUST PRINCIPLE: Identity Verification
        
        This is the entry point for CAC/PIV authentication. The reverse proxy
        has already verified the certificate cryptographically. We extract
        the identity information for use in authorization decisions.
        
        Args:
            headers: HTTP headers dictionary from request
        
        Returns:
            CACIdentity if valid certificate present, None otherwise
        
        Example:
            identity = handler.extract_identity_from_headers(request.headers)
            if identity:
                session = create_session(user_id=identity.edipi, ...)
        """
        # Check if certificate was verified by proxy
        verify_status = headers.get(self.HEADER_CLIENT_VERIFY, '')
        if verify_status.upper() not in ('SUCCESS', 'OK', 'NONE'):
            logger.debug(f"Certificate verification status: {verify_status}")
            return None
        
        # Get subject DN
        client_dn = headers.get(self.HEADER_CLIENT_DN)
        if not client_dn:
            logger.debug("No client DN in headers")
            return None
        
        # Parse the DN
        identity = self._parse_dn(client_dn)
        if not identity:
            logger.warning(f"Failed to parse client DN: {client_dn}")
            return None
        
        # Add issuer info if available
        issuer = headers.get(self.HEADER_CLIENT_ISSUER)
        if issuer:
            identity.issuer = issuer
            
            # Optionally verify issuer is trusted
            if self.trusted_issuers and not self._is_trusted_issuer(issuer):
                logger.warning(f"Untrusted certificate issuer: {issuer}")
                return None
        
        # Add serial number if available
        serial = headers.get(self.HEADER_CLIENT_SERIAL)
        if serial:
            identity.serial_number = serial
        
        logger.info(f"CAC/PIV identity extracted: EDIPI={identity.edipi}")
        return identity
    
    def _parse_dn(self, dn: str) -> Optional[CACIdentity]:
        """
        Parse Distinguished Name to extract identity fields
        
        Args:
            dn: Distinguished Name string from certificate
        
        Returns:
            CACIdentity if parsing succeeds, None otherwise
        """
        # Extract Common Name (CN)
        cn_match = re.search(r'CN=([^,]+)', dn, re.IGNORECASE)
        if not cn_match:
            return None
        
        common_name = cn_match.group(1).strip()
        
        # Try to parse as DoD CAC format
        cac_match = self.CAC_CN_PATTERN.match(common_name)
        if cac_match:
            return CACIdentity(
                common_name=common_name,
                last_name=cac_match.group('last').title(),
                first_name=cac_match.group('first').title(),
                middle_name=cac_match.group('middle').title() if cac_match.group('middle') else None,
                edipi=cac_match.group('edipi'),
                email=self._extract_email(dn),
                organization=self._extract_org(dn),
                issuer=None,
                serial_number=None,
                valid_from=None,
                valid_to=None,
                auth_method="CAC"
            )
        
        # If not CAC format, try PIV format (may vary by agency)
        # Fall back to using CN as-is with generated identifier
        logger.debug(f"CN does not match CAC format: {common_name}")
        return None
    
    def _extract_email(self, dn: str) -> Optional[str]:
        """Extract email address from DN if present"""
        match = self.EMAIL_PATTERN.search(dn)
        return match.group(1) if match else None
    
    def _extract_org(self, dn: str) -> Optional[str]:
        """Extract organization from DN if present"""
        match = re.search(r'O=([^,]+)', dn, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    def _is_trusted_issuer(self, issuer: str) -> bool:
        """Check if issuer is in trusted list"""
        if not self.trusted_issuers:
            return True
        
        for trusted in self.trusted_issuers:
            if trusted.lower() in issuer.lower():
                return True
        
        return False


# =============================================================================
# FLASK INTEGRATION
# =============================================================================

def require_cac_auth(f):
    """
    Flask decorator requiring CAC/PIV authentication
    
    ZERO TRUST PRINCIPLE: Strong Identity Verification
    
    This decorator ensures the user has authenticated via CAC/PIV card.
    Use this for endpoints that require strong identity assurance.
    
    Usage:
        @app.route('/api/sensitive-data')
        @require_cac_auth
        def get_sensitive_data():
            edipi = g.cac_identity.edipi
            ...
    
    Federal Mapping: NIST IA-2(1) (MFA for Privileged Accounts)
    """
    from functools import wraps
    
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            from flask import request, jsonify, g
        except ImportError:
            raise RuntimeError("Flask required for this decorator")
        
        handler = CACPIVHandler()
        identity = handler.extract_identity_from_headers(dict(request.headers))
        
        if not identity:
            logger.warning(f"CAC auth required but not provided: {request.remote_addr}")
            return jsonify({
                "error": "CAC/PIV authentication required",
                "hint": "Please ensure your CAC/PIV card is inserted and PIN entered"
            }), 401
        
        # Attach identity to request context
        g.cac_identity = identity
        g.auth_method = "CAC"
        
        return f(*args, **kwargs)
    
    return decorated


# =============================================================================
# NGINX CONFIGURATION EXAMPLE
# =============================================================================

NGINX_CONFIG_EXAMPLE = """
# Example nginx configuration for CAC/PIV authentication
# 
# This configuration:
# 1. Enables TLS client certificate authentication
# 2. Verifies certificates against DoD CA bundle
# 3. Passes certificate info to application via headers

server {
    listen 443 ssl;
    server_name app.example.mil;
    
    # Server certificate
    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    
    # CA bundle for verifying client certificates (DoD PKI)
    # Download from: https://public.cyber.mil/pki-pke/
    ssl_client_certificate /etc/nginx/certs/DoD_PKE_CA_chain.pem;
    
    # Require client certificate
    ssl_verify_client on;
    ssl_verify_depth 4;
    
    # TLS settings (STIG compliant)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    
    location / {
        proxy_pass http://app:8000;
        
        # Pass certificate info to application
        proxy_set_header X-SSL-Client-DN $ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
        proxy_set_header X-SSL-Client-Issuer $ssl_client_i_dn;
        proxy_set_header X-SSL-Client-Serial $ssl_client_serial;
        
        # Standard proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
"""


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def validate_edipi(edipi: str) -> bool:
    """
    Validate EDIPI format
    
    EDIPI (Electronic Data Interchange Personal Identifier) is a unique
    10-digit number assigned to DoD personnel, contractors, and affiliates.
    
    Args:
        edipi: String to validate
    
    Returns:
        True if valid EDIPI format, False otherwise
    """
    if not edipi:
        return False
    
    # EDIPI is exactly 10 digits
    if not re.match(r'^\d{10}$', edipi):
        return False
    
    return True


def lookup_user_by_edipi(edipi: str, user_store) -> Optional[Dict[str, Any]]:
    """
    Look up user in local store by EDIPI
    
    ZERO TRUST: Just-In-Time Account Provisioning
    
    In Zero Trust architectures, you may want to:
    1. Look up user by EDIPI from CAC
    2. If not found, provision account just-in-time
    3. Assign default least-privilege permissions
    
    Args:
        edipi: User's EDIPI from CAC certificate
        user_store: User storage backend
    
    Returns:
        User record if found, None otherwise
    """
    # This is a stub - implement based on your user store
    return user_store.get_by_edipi(edipi)


def provision_user_from_cac(identity: CACIdentity, user_store) -> Dict[str, Any]:
    """
    Provision new user account from CAC identity
    
    ZERO TRUST: Just-In-Time Provisioning
    
    When a user authenticates via CAC for the first time, create their
    account with default minimal permissions. This follows least-privilege
    principle - users get only what they need.
    
    Args:
        identity: Parsed CAC identity
        user_store: User storage backend
    
    Returns:
        Newly created user record
    """
    user = {
        "user_id": identity.edipi,
        "username": identity.edipi,
        "display_name": identity.get_display_name(),
        "email": identity.email,
        "first_name": identity.first_name,
        "last_name": identity.last_name,
        "auth_method": "CAC",
        "roles": ["user"],  # Default minimal role
        "created_at": datetime.utcnow().isoformat(),
        "provisioned_from": "CAC"
    }
    
    user_store.create(user)
    
    logger.info(f"Provisioned new user from CAC: EDIPI={identity.edipi}")
    return user
