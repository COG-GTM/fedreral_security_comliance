# Zero Trust Development Playbook for Devin

> Copy this entire file to your Devin Playbooks.

## Purpose

This playbook guides Devin through generating code that implements Zero Trust Architecture principles. Each step explains WHAT to do, WHY it matters, and HOW it maps to federal security requirements.

---

## When to Apply

**Always** - Zero Trust principles apply to ALL code generation, especially:
- Authentication/authorization systems
- API endpoints
- Session management
- Data access layers
- Any user-facing functionality

---

## Step 0: Zero Trust Mindset Check

Before writing any code, ask:

| Question | If YES | If NO |
|----------|--------|-------|
| Does this handle user input? | Apply validation + sanitization | Continue |
| Does this check identity? | Verify on EVERY request | Add verification |
| Does this access data? | Check authorization + log access | Add auth check |
| Does this create/manage sessions? | Bind to IP + set 15-min timeout | Add binding |
| Could this leak information? | Return generic errors only | Continue |

**Zero Trust Mantra:** "Never trust, always verify."

---

## Step 1: Verify Identity on Every Request

### Why This Step Exists

Traditional security verifies identity once at login. Zero Trust verifies on EVERY request because:
- Tokens can be stolen
- Sessions can be hijacked
- Network position doesn't equal trust

### What to Generate

```python
from functools import wraps
from flask import request, jsonify

def require_verified_identity(f):
    """
    Zero Trust: Continuous Identity Verification
    
    This decorator ensures EVERY request to protected endpoints
    carries a verified identity. No exceptions.
    
    Maps to: NIST IA-2 (Identification and Authentication)
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Extract session token
        session_id = request.cookies.get('session_id')
        if not session_id:
            # No identity presented - reject immediately
            audit_log("auth_missing", None, request.remote_addr)
            return jsonify({"error": "Authentication required"}), 401
        
        # Verify session is valid AND matches current context
        session = validate_session(session_id, request.remote_addr)
        if not session:
            audit_log("auth_invalid", None, request.remote_addr)
            return jsonify({"error": "Invalid session"}), 401
        
        # Attach verified identity to request for downstream use
        request.verified_user = session.user_id
        request.session = session
        
        return f(*args, **kwargs)
    return decorated
```

### Verification Checklist

- [ ] Session token present in request
- [ ] Session exists in store
- [ ] Session not expired (15-min timeout)
- [ ] Session IP matches request IP
- [ ] User account not locked/disabled

---

## Step 2: Implement Session IP Binding

### Why This Step Exists

If an attacker steals a session token, IP binding makes it useless unless they also control the victim's IP address. This is a core Zero Trust defense against session hijacking.

### What to Generate

```python
def create_session(user_id: str, ip_address: str, user_agent: str) -> Session:
    """
    Zero Trust: IP-Bound Sessions
    
    Sessions are bound to the IP address that created them.
    If a request comes from a different IP, the session is invalid.
    
    WHY: Stolen session tokens are useless without the original IP.
    This significantly raises the bar for attackers.
    
    Maps to: STIG V-220630 (Session Management)
    """
    session = Session(
        session_id=secrets.token_urlsafe(32),
        user_id=user_id,
        ip_address=ip_address,  # CRITICAL: Bind to IP
        user_agent=user_agent,
        created_at=datetime.utcnow(),
        last_activity=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=15)
    )
    
    store_session(session)
    
    audit_log("session_created", user_id, ip_address, {
        "session_id": session.session_id,
        "bound_ip": ip_address
    })
    
    return session


def validate_session(session_id: str, request_ip: str) -> Optional[Session]:
    """
    Zero Trust: Continuous Session Validation
    
    Every request must pass these checks:
    1. Session exists
    2. Session not expired
    3. Request IP matches bound IP
    
    If ANY check fails, the session is invalid.
    """
    session = get_session(session_id)
    
    if not session:
        return None
    
    # Check expiration (15-minute timeout)
    if datetime.utcnow() > session.expires_at:
        destroy_session(session_id)
        audit_log("session_expired", session.user_id, request_ip)
        return None
    
    # Check IP binding - CRITICAL for Zero Trust
    if session.ip_address != request_ip:
        # Possible session hijacking attempt
        audit_log("session_ip_mismatch", session.user_id, request_ip, {
            "expected_ip": session.ip_address,
            "actual_ip": request_ip,
            "threat": "possible_session_hijacking"
        })
        destroy_session(session_id)
        return None
    
    # Update last activity (sliding expiration)
    session.last_activity = datetime.utcnow()
    session.expires_at = datetime.utcnow() + timedelta(minutes=15)
    update_session(session)
    
    return session
```

### IP Binding Considerations

| Scenario | Handling |
|----------|----------|
| User behind NAT | All users share IP - still works |
| User on VPN | VPN IP is bound - still works |
| User IP changes (mobile) | Session invalidates - user re-auths |
| Load balancer in front | Use `X-Forwarded-For` header (with caution) |

---

## Step 3: Regenerate Session After Authentication

### Why This Step Exists

**Session Fixation Attack:** An attacker tricks a user into using a session ID the attacker knows. When the user logs in, the attacker has a valid authenticated session.

**Defense:** Generate a NEW session ID after successful authentication, invalidating any pre-existing session ID.

### What to Generate

```python
def authenticate_user(username: str, password: str, request_ip: str) -> dict:
    """
    Zero Trust: Session Regeneration Post-Authentication
    
    After successful login, we MUST create a new session ID.
    Any existing session (even if valid) is destroyed.
    
    WHY: Prevents session fixation attacks where attacker
    pre-sets a session ID and waits for victim to authenticate.
    
    Maps to: STIG V-220630, OWASP Session Management
    """
    # Verify credentials
    user = verify_credentials(username, password)
    if not user:
        audit_log("login_failed", None, request_ip, {
            "username": username,
            "reason": "invalid_credentials"
        })
        return {"success": False, "error": "Invalid credentials"}
    
    # Check account lockout
    if user.is_locked():
        audit_log("login_blocked", user.id, request_ip, {
            "reason": "account_locked"
        })
        return {"success": False, "error": "Account locked"}
    
    # CRITICAL: Destroy any existing session for this user
    # WHY: Prevents session fixation AND ensures single-session
    existing_sessions = get_sessions_for_user(user.id)
    for session in existing_sessions:
        destroy_session(session.session_id)
    
    # Create NEW session with NEW ID
    new_session = create_session(
        user_id=user.id,
        ip_address=request_ip,
        user_agent=request.headers.get('User-Agent', '')
    )
    
    audit_log("login_success", user.id, request_ip, {
        "session_id": new_session.session_id,
        "previous_sessions_destroyed": len(existing_sessions)
    })
    
    return {
        "success": True,
        "session_id": new_session.session_id,
        "expires_in": 900  # 15 minutes in seconds
    }
```

---

## Step 4: Implement Least Privilege Authorization

### Why This Step Exists

Zero Trust requires that users get ONLY the permissions they need, ONLY when they need them. This limits blast radius if an account is compromised.

### What to Generate

```python
def check_permission(user_id: str, resource: str, action: str, context: dict) -> bool:
    """
    Zero Trust: Least Privilege Authorization
    
    Access is granted only if:
    1. User has explicit permission for this resource+action
    2. Context allows it (time, location, device)
    3. No conflicting deny rules exist
    
    DEFAULT IS DENY. Access must be explicitly granted.
    
    Maps to: NIST AC-6 (Least Privilege), AC-3 (Access Enforcement)
    """
    # Get user's assigned permissions
    user_permissions = get_user_permissions(user_id)
    
    # Check for explicit grant
    required_permission = f"{resource}:{action}"
    has_permission = required_permission in user_permissions
    
    if not has_permission:
        audit_log("permission_denied", user_id, context.get("ip"), {
            "resource": resource,
            "action": action,
            "reason": "no_explicit_grant"
        })
        return False
    
    # Apply context-based restrictions
    # WHY: Same permission might not apply in all contexts
    
    # Time-based restriction
    if is_after_hours() and not user_has_after_hours_access(user_id):
        audit_log("permission_denied", user_id, context.get("ip"), {
            "resource": resource,
            "action": action,
            "reason": "after_hours_restriction"
        })
        return False
    
    # Location-based restriction
    if context.get("location") == "external":
        if not permission_allows_external(required_permission):
            audit_log("permission_denied", user_id, context.get("ip"), {
                "resource": resource,
                "action": action,
                "reason": "external_access_restricted"
            })
            return False
    
    # Permission granted - log it
    audit_log("permission_granted", user_id, context.get("ip"), {
        "resource": resource,
        "action": action
    })
    
    return True
```

### Permission Patterns

```python
# Example permission structure
PERMISSIONS = {
    "user:basic": [
        "profile:read",
        "profile:update_own",
        "data:read_own"
    ],
    "user:elevated": [
        "profile:read",
        "profile:update_own",
        "data:read_own",
        "data:read_team",
        "reports:generate"
    ],
    "admin": [
        "profile:read",
        "profile:update_any",
        "data:read_all",
        "data:modify_all",
        "users:manage",
        "audit:view"
    ]
}
```

---

## Step 5: Log Everything for Audit Trail

### Why This Step Exists

Zero Trust requires full visibility into all actions. Audit logs enable:
- Incident investigation (what happened?)
- Compliance proof (did we follow policy?)
- Anomaly detection (is this normal behavior?)

### What to Generate

```python
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

class ZeroTrustAuditLogger:
    """
    Zero Trust: Comprehensive Audit Logging
    
    Every security-relevant event must be logged with:
    - WHO: User identity (or "anonymous")
    - WHAT: Action attempted
    - WHEN: Timestamp (UTC, ISO 8601)
    - WHERE: IP address, resource
    - OUTCOME: Success or failure
    - WHY: Reason for failure (if applicable)
    
    Maps to: NIST AU-2 (Audit Events), AU-3 (Audit Content)
             STIG V-220635 (Audit Logging)
    """
    
    # Events that MUST be logged per federal requirements
    REQUIRED_EVENTS = [
        "login_success",
        "login_failed",
        "logout",
        "session_created",
        "session_expired",
        "session_ip_mismatch",
        "permission_granted",
        "permission_denied",
        "data_access",
        "data_modification",
        "admin_action",
        "security_violation"
    ]
    
    def __init__(self):
        self.logger = logging.getLogger("zero_trust_audit")
        self.logger.setLevel(logging.INFO)
    
    def log(
        self,
        event_type: str,
        user_id: Optional[str],
        ip_address: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log a security event in structured JSON format.
        
        WHY JSON: Machine-parseable for SIEM integration,
        human-readable for manual review.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "user_id": user_id or "anonymous",
            "ip_address": ip_address,
            "details": details or {}
        }
        
        # Add correlation ID for request tracing
        entry["correlation_id"] = get_current_correlation_id()
        
        # Determine severity
        if "failed" in event_type or "denied" in event_type or "violation" in event_type:
            entry["severity"] = "WARNING"
        elif "mismatch" in event_type:
            entry["severity"] = "ERROR"
        else:
            entry["severity"] = "INFO"
        
        self.logger.info(json.dumps(entry))
```

### Required Audit Events

| Event | When to Log | Why It Matters |
|-------|-------------|----------------|
| `login_success` | User authenticates | Track who accessed system |
| `login_failed` | Auth fails | Detect brute force |
| `session_ip_mismatch` | IP changes mid-session | Detect hijacking |
| `permission_denied` | Access blocked | Track unauthorized attempts |
| `data_access` | Data read | Compliance trail |
| `data_modification` | Data changed | Change tracking |
| `admin_action` | Privileged operation | Accountability |

---

## Step 6: Handle Errors Without Information Leakage

### Why This Step Exists

Error messages can leak sensitive information. Zero Trust extends to information flow - don't trust that the requester should know internal details.

### What to Generate

```python
def handle_request_safely(handler_func):
    """
    Zero Trust: Information Leakage Prevention
    
    Internal errors must not leak to external users.
    - Log detailed error internally
    - Return generic message externally
    
    WHY: Attackers use error messages to probe systems.
    Detailed errors reveal internal structure.
    
    Maps to: STIG V-220641 (Error Handling)
    """
    @wraps(handler_func)
    def wrapper(*args, **kwargs):
        try:
            return handler_func(*args, **kwargs)
        except ValidationError as e:
            # Validation errors can be somewhat specific
            # (user needs to know what to fix)
            audit_log("validation_error", get_current_user(), request.remote_addr, {
                "error": str(e),
                "endpoint": request.path
            })
            return jsonify({"error": "Invalid input", "field": e.field}), 400
        
        except PermissionError as e:
            # Don't reveal what permission was missing
            audit_log("permission_error", get_current_user(), request.remote_addr, {
                "error": str(e),
                "endpoint": request.path
            })
            return jsonify({"error": "Access denied"}), 403
        
        except Exception as e:
            # CRITICAL: Log full error internally, return generic message
            audit_log("internal_error", get_current_user(), request.remote_addr, {
                "error": str(e),
                "traceback": traceback.format_exc(),
                "endpoint": request.path
            })
            # Generic message - reveals nothing about internals
            return jsonify({"error": "An error occurred"}), 500
    
    return wrapper
```

---

## Quick Reference Card

### Every Endpoint Must:

```python
@app.route("/api/resource", methods=["GET", "POST"])
@require_verified_identity  # Step 1: Verify identity
@handle_request_safely      # Step 6: Safe error handling
def handle_resource():
    user_id = request.verified_user
    client_ip = request.remote_addr
    
    # Step 4: Check permission
    if not check_permission(user_id, "resource", "read", {"ip": client_ip}):
        return jsonify({"error": "Access denied"}), 403
    
    # Step 5: Log the access
    audit_log("data_access", user_id, client_ip, {
        "resource": "resource",
        "action": "read"
    })
    
    # Process request...
    return jsonify({"data": result})
```

### Session Lifecycle:

1. **Login** → Verify creds → Destroy old sessions → Create new IP-bound session
2. **Each Request** → Validate session → Check IP binding → Check timeout → Update activity
3. **Logout** → Destroy session → Log event

---

## Important Note

**Devin is not FedRAMP certified.** This playbook teaches Devin to generate Zero Trust-compliant code. The generated code should be reviewed and deployed in an authorized environment.

---

**Reference:** NIST SP 800-207, STIG Application Security
