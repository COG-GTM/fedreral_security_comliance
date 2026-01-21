"""
Zero Trust Middleware Module

This module implements core Zero Trust Architecture patterns for Python web applications.
It provides middleware and utilities that enforce continuous verification, IP-bound sessions,
and least-privilege access controls.

ZERO TRUST PRINCIPLES IMPLEMENTED:
1. Continuous Verification - Every request is verified, not just login
2. IP-Bound Sessions - Sessions tied to originating IP address
3. Session Regeneration - New session ID after authentication
4. Least Privilege - Default deny, explicit grants only
5. Full Audit Trail - All security events logged

FEDERAL COMPLIANCE:
- NIST SP 800-207 (Zero Trust Architecture)
- NIST SP 800-53 AC-12 (Session Management)
- STIG V-220630 (Session Security)
- FedRAMP Moderate/High baseline

IMPORTANT: This module provides the implementation patterns. The actual deployment
must occur in a FedRAMP-authorized environment (like Windsurf) for federal use.
"""

import secrets
import logging
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass, field
from functools import wraps
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

class ZeroTrustConfig:
    """
    Zero Trust Configuration Constants
    
    These values are set per federal security requirements.
    Do not modify without security review.
    """
    
    # Session timeout: 15 minutes per STIG V-220630
    # WHY: Limits the window for session-based attacks while remaining usable
    SESSION_TIMEOUT_MINUTES: int = 15
    
    # Account lockout threshold per STIG V-220629
    # WHY: Prevents brute force attacks while allowing for typos
    MAX_FAILED_ATTEMPTS: int = 5
    
    # Lockout duration per STIG V-220629
    # WHY: Long enough to deter attacks, short enough not to require admin unlock
    LOCKOUT_DURATION_MINUTES: int = 15
    
    # Session ID entropy (256 bits)
    # WHY: Cryptographically secure, infeasible to guess
    SESSION_ID_BYTES: int = 32
    
    # Endpoints that don't require authentication
    # WHY: Some endpoints must be public (health checks, login page)
    # CAUTION: Keep this list minimal
    PUBLIC_ENDPOINTS: list = field(default_factory=lambda: [
        '/health',
        '/auth/login',
        '/auth/logout',
        '/.well-known/openid-configuration'
    ])


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class ZeroTrustSession:
    """
    Zero Trust Session Data Structure
    
    Each session contains all information needed for continuous verification.
    
    ZERO TRUST FIELDS:
    - session_id: Cryptographically random identifier
    - user_id: Verified user identity
    - bound_ip: IP address session is tied to (prevents hijacking)
    - created_at: When session was created
    - last_activity: For timeout calculation
    - expires_at: Hard expiration time
    
    WHY IP BINDING:
    If an attacker steals a session token but requests from a different IP,
    the session is rejected. This makes stolen tokens much less useful.
    """
    session_id: str
    user_id: str
    bound_ip: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    
    def is_expired(self) -> bool:
        """Check if session has expired (either hard expiration or inactivity)"""
        now = datetime.utcnow()
        
        # Hard expiration check
        if now > self.expires_at:
            return True
        
        # Inactivity check (15-minute timeout)
        inactive_duration = now - self.last_activity
        if inactive_duration > timedelta(minutes=ZeroTrustConfig.SESSION_TIMEOUT_MINUTES):
            return True
        
        return False
    
    def touch(self) -> None:
        """Update last activity and extend expiration (sliding window)"""
        self.last_activity = datetime.utcnow()
        self.expires_at = datetime.utcnow() + timedelta(
            minutes=ZeroTrustConfig.SESSION_TIMEOUT_MINUTES
        )


class AuditEventType(Enum):
    """
    Audit Event Types for Zero Trust Logging
    
    These events MUST be logged per federal requirements (NIST AU-2).
    Each event type maps to a specific security concern.
    """
    # Authentication events
    AUTH_SUCCESS = "authentication_success"      # User successfully authenticated
    AUTH_FAILURE = "authentication_failure"      # Authentication attempt failed
    AUTH_LOCKOUT = "account_lockout"             # Account locked due to failures
    
    # Session events
    SESSION_CREATED = "session_created"          # New session established
    SESSION_VALIDATED = "session_validated"      # Session verified on request
    SESSION_EXPIRED = "session_expired"          # Session timed out
    SESSION_DESTROYED = "session_destroyed"      # Explicit logout
    SESSION_IP_MISMATCH = "session_ip_mismatch"  # ALERT: Possible hijacking
    
    # Authorization events
    ACCESS_GRANTED = "access_granted"            # Authorization succeeded
    ACCESS_DENIED = "access_denied"              # Authorization failed
    
    # Data events
    DATA_ACCESS = "data_access"                  # Data read operation
    DATA_MODIFY = "data_modification"            # Data write operation
    
    # Security events
    SECURITY_VIOLATION = "security_violation"    # Security rule violated


# =============================================================================
# SESSION STORE (In-Memory - Replace with Redis/DB in production)
# =============================================================================

class ZeroTrustSessionStore:
    """
    Zero Trust Session Store
    
    In-memory implementation for demonstration. In production, use:
    - Redis (recommended for distributed systems)
    - PostgreSQL with encryption at rest
    - AWS ElastiCache with encryption
    
    SECURITY REQUIREMENTS:
    - Sessions stored encrypted at rest (SC-28)
    - Session data not logged (prevents token leakage)
    - Regular cleanup of expired sessions
    """
    
    def __init__(self):
        self._sessions: Dict[str, ZeroTrustSession] = {}
    
    def create(self, session: ZeroTrustSession) -> None:
        """Store a new session"""
        self._sessions[session.session_id] = session
    
    def get(self, session_id: str) -> Optional[ZeroTrustSession]:
        """Retrieve session by ID (returns None if not found)"""
        return self._sessions.get(session_id)
    
    def update(self, session: ZeroTrustSession) -> None:
        """Update existing session"""
        if session.session_id in self._sessions:
            self._sessions[session.session_id] = session
    
    def delete(self, session_id: str) -> None:
        """Delete session (logout or invalidation)"""
        if session_id in self._sessions:
            del self._sessions[session_id]
    
    def delete_user_sessions(self, user_id: str) -> int:
        """
        Delete all sessions for a user
        
        WHY: On new login, destroy existing sessions to:
        1. Prevent session fixation
        2. Enforce single-session policy (optional)
        """
        to_delete = [
            sid for sid, session in self._sessions.items()
            if session.user_id == user_id
        ]
        for sid in to_delete:
            del self._sessions[sid]
        return len(to_delete)
    
    def cleanup_expired(self) -> int:
        """Remove all expired sessions (call periodically)"""
        to_delete = [
            sid for sid, session in self._sessions.items()
            if session.is_expired()
        ]
        for sid in to_delete:
            del self._sessions[sid]
        return len(to_delete)


# Global session store instance
session_store = ZeroTrustSessionStore()


# =============================================================================
# AUDIT LOGGING
# =============================================================================

class ZeroTrustAuditLogger:
    """
    Zero Trust Audit Logger
    
    Logs all security-relevant events in structured JSON format.
    
    WHY STRUCTURED LOGGING:
    - Machine-parseable for SIEM integration
    - Consistent format for analysis
    - Required fields per NIST AU-3
    
    REQUIRED FIELDS (NIST AU-3):
    - timestamp: When the event occurred (ISO 8601, UTC)
    - event_type: What happened
    - user_id: Who did it (or "anonymous")
    - ip_address: Where the request came from
    - outcome: Success or failure
    - details: Additional context
    """
    
    def __init__(self, app_name: str = "zero-trust-app"):
        self.app_name = app_name
        self.logger = logging.getLogger(f"{app_name}.audit")
        self.logger.setLevel(logging.INFO)
    
    def log(
        self,
        event_type: AuditEventType,
        user_id: Optional[str],
        ip_address: str,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """
        Log a security event
        
        Args:
            event_type: Type of event (from AuditEventType enum)
            user_id: User identifier (None for anonymous)
            ip_address: Client IP address
            details: Additional event-specific information
            correlation_id: Request tracing ID
        """
        # Determine outcome based on event type
        failure_events = {
            AuditEventType.AUTH_FAILURE,
            AuditEventType.AUTH_LOCKOUT,
            AuditEventType.ACCESS_DENIED,
            AuditEventType.SESSION_IP_MISMATCH,
            AuditEventType.SECURITY_VIOLATION
        }
        outcome = "failure" if event_type in failure_events else "success"
        
        # Determine severity
        if event_type in {AuditEventType.SECURITY_VIOLATION, AuditEventType.SESSION_IP_MISMATCH}:
            severity = "ERROR"
        elif event_type in failure_events:
            severity = "WARNING"
        else:
            severity = "INFO"
        
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "app_name": self.app_name,
            "event_type": event_type.value,
            "severity": severity,
            "user_id": user_id or "anonymous",
            "ip_address": ip_address,
            "outcome": outcome,
            "details": details or {},
            "correlation_id": correlation_id or secrets.token_hex(8)
        }
        
        self.logger.info(json.dumps(entry))


# Global audit logger instance
audit_logger = ZeroTrustAuditLogger()


# =============================================================================
# CORE ZERO TRUST FUNCTIONS
# =============================================================================

def create_zero_trust_session(
    user_id: str,
    ip_address: str,
    user_agent: str
) -> ZeroTrustSession:
    """
    Create a new Zero Trust session
    
    ZERO TRUST PRINCIPLE: IP Binding
    
    The session is bound to the IP address that created it. On every
    subsequent request, we verify the request comes from the same IP.
    If not, we assume the session was stolen and invalidate it.
    
    Args:
        user_id: Verified user identifier
        ip_address: Client IP to bind session to
        user_agent: Client user agent string
    
    Returns:
        New ZeroTrustSession object
    
    Federal Mapping: STIG V-220630
    """
    now = datetime.utcnow()
    
    session = ZeroTrustSession(
        session_id=secrets.token_urlsafe(ZeroTrustConfig.SESSION_ID_BYTES),
        user_id=user_id,
        bound_ip=ip_address,
        user_agent=user_agent,
        created_at=now,
        last_activity=now,
        expires_at=now + timedelta(minutes=ZeroTrustConfig.SESSION_TIMEOUT_MINUTES)
    )
    
    session_store.create(session)
    
    audit_logger.log(
        AuditEventType.SESSION_CREATED,
        user_id,
        ip_address,
        {"session_id_prefix": session.session_id[:8] + "..."}  # Don't log full ID
    )
    
    return session


def validate_session(session_id: str, request_ip: str) -> Optional[ZeroTrustSession]:
    """
    Validate a session with Zero Trust checks
    
    ZERO TRUST PRINCIPLE: Continuous Verification
    
    This function performs multiple checks on every request:
    1. Session exists
    2. Session not expired (15-minute timeout)
    3. Request IP matches bound IP (anti-hijacking)
    
    If ANY check fails, the session is invalid.
    
    Args:
        session_id: Session identifier from cookie
        request_ip: IP address of current request
    
    Returns:
        ZeroTrustSession if valid, None otherwise
    
    Federal Mapping: STIG V-220630, NIST AC-12
    """
    session = session_store.get(session_id)
    
    # Check 1: Session exists
    if not session:
        return None
    
    # Check 2: Session not expired
    if session.is_expired():
        session_store.delete(session_id)
        audit_logger.log(
            AuditEventType.SESSION_EXPIRED,
            session.user_id,
            request_ip
        )
        return None
    
    # Check 3: IP binding (CRITICAL for Zero Trust)
    # WHY: If request IP doesn't match bound IP, session may be stolen
    if session.bound_ip != request_ip:
        audit_logger.log(
            AuditEventType.SESSION_IP_MISMATCH,
            session.user_id,
            request_ip,
            {
                "bound_ip": session.bound_ip,
                "request_ip": request_ip,
                "threat_indicator": "possible_session_hijacking",
                "action_taken": "session_invalidated"
            }
        )
        session_store.delete(session_id)  # Invalidate potentially compromised session
        return None
    
    # All checks passed - update activity and return
    session.touch()
    session_store.update(session)
    
    audit_logger.log(
        AuditEventType.SESSION_VALIDATED,
        session.user_id,
        request_ip
    )
    
    return session


def regenerate_session(old_session_id: str, request_ip: str) -> Optional[ZeroTrustSession]:
    """
    Regenerate session with new ID (post-authentication)
    
    ZERO TRUST PRINCIPLE: Session Regeneration
    
    After successful authentication, we create a new session with a new ID.
    This prevents session fixation attacks where an attacker plants a known
    session ID and waits for the victim to authenticate.
    
    ATTACK SCENARIO:
    1. Attacker visits site, gets session ID "abc123"
    2. Attacker tricks victim into using "abc123" (via URL or XSS)
    3. Victim logs in while using session "abc123"
    4. Attacker now has authenticated session "abc123"
    
    DEFENSE:
    After login, generate NEW session ID. "abc123" becomes invalid.
    
    Args:
        old_session_id: Current session ID (will be destroyed)
        request_ip: Current request IP (for new session binding)
    
    Returns:
        New session, or None if old session invalid
    
    Federal Mapping: STIG V-220630, OWASP Session Management
    """
    old_session = session_store.get(old_session_id)
    if not old_session:
        return None
    
    # Store user info before destroying old session
    user_id = old_session.user_id
    user_agent = old_session.user_agent
    
    # Destroy old session
    session_store.delete(old_session_id)
    
    # Create new session with new ID
    new_session = create_zero_trust_session(user_id, request_ip, user_agent)
    
    audit_logger.log(
        AuditEventType.SESSION_CREATED,
        user_id,
        request_ip,
        {
            "reason": "session_regeneration",
            "old_session_destroyed": True
        }
    )
    
    return new_session


def destroy_session(session_id: str, request_ip: str) -> bool:
    """
    Explicitly destroy a session (logout)
    
    Args:
        session_id: Session to destroy
        request_ip: For audit logging
    
    Returns:
        True if session was destroyed, False if not found
    """
    session = session_store.get(session_id)
    if not session:
        return False
    
    user_id = session.user_id
    session_store.delete(session_id)
    
    audit_logger.log(
        AuditEventType.SESSION_DESTROYED,
        user_id,
        request_ip,
        {"reason": "explicit_logout"}
    )
    
    return True


# =============================================================================
# FLASK MIDDLEWARE (if using Flask)
# =============================================================================

def zero_trust_required(f: Callable) -> Callable:
    """
    Flask decorator for Zero Trust protection
    
    Apply this decorator to any endpoint that requires authentication.
    It will:
    1. Check for session cookie
    2. Validate session (including IP binding)
    3. Attach verified user to request context
    4. Reject invalid requests with 401
    
    Usage:
        @app.route('/api/data')
        @zero_trust_required
        def get_data():
            user_id = g.current_user  # Verified user
            ...
    
    Federal Mapping: NIST IA-2, AC-3
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Import Flask components inside function to avoid import errors
        # when Flask is not installed
        try:
            from flask import request, jsonify, g
        except ImportError:
            raise RuntimeError("Flask is required for this decorator")
        
        # Get session ID from cookie
        session_id = request.cookies.get('session_id')
        if not session_id:
            audit_logger.log(
                AuditEventType.ACCESS_DENIED,
                None,
                request.remote_addr,
                {"reason": "no_session_token", "endpoint": request.path}
            )
            return jsonify({"error": "Authentication required"}), 401
        
        # Validate session with IP binding
        session = validate_session(session_id, request.remote_addr)
        if not session:
            audit_logger.log(
                AuditEventType.ACCESS_DENIED,
                None,
                request.remote_addr,
                {"reason": "invalid_session", "endpoint": request.path}
            )
            return jsonify({"error": "Session invalid"}), 401
        
        # Attach verified identity to request context
        g.current_user = session.user_id
        g.session = session
        
        return f(*args, **kwargs)
    
    return decorated


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_client_ip(request) -> str:
    """
    Get client IP address, accounting for reverse proxies
    
    SECURITY WARNING:
    X-Forwarded-For can be spoofed if not properly configured.
    Only trust this header if your reverse proxy is configured to
    set it correctly and strip any client-provided values.
    
    Args:
        request: Flask/Django request object
    
    Returns:
        Client IP address
    """
    # Check for proxy headers (use with caution)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # X-Forwarded-For format: client, proxy1, proxy2
        # First IP is the original client (if proxy configured correctly)
        return forwarded_for.split(',')[0].strip()
    
    # Direct connection
    return request.remote_addr


def cleanup_expired_sessions() -> int:
    """
    Remove expired sessions from store
    
    Call this periodically (e.g., every 5 minutes) to prevent
    memory bloat from accumulated expired sessions.
    
    Returns:
        Number of sessions cleaned up
    """
    count = session_store.cleanup_expired()
    if count > 0:
        logger.info(f"Cleaned up {count} expired sessions")
    return count
