# Zero Trust Security Knowledge for Devin

> Copy this entire file to your Devin Knowledge base.

## What is Zero Trust?

**Zero Trust** is a security model based on the principle: **"Never trust, always verify."**

Unlike traditional perimeter-based security (where anything inside the network is trusted), Zero Trust assumes that threats can exist both inside and outside the network. Every user, device, and network flow must be authenticated and authorized continuously.

### Why This Matters for Code Generation

When Devin generates code, it must produce applications that enforce Zero Trust principles. This means:
- No implicit trust based on network location
- Every request must carry verified identity
- Sessions must be continuously validated
- All actions must be logged for audit

---

## The Five Pillars of Zero Trust (NIST SP 800-207)

Understanding these pillars helps you generate compliant code:

| Pillar | Principle | Code Implication |
|--------|-----------|------------------|
| **Identity** | Verify every user | Implement strong authentication (MFA, CAC/PIV) |
| **Device** | Verify every device | Check device certificates, validate posture |
| **Network** | Segment and isolate | No cross-tenant data access, micro-segmentation |
| **Application** | Secure by default | Default-deny access, explicit grants only |
| **Data** | Protect everywhere | Encrypt at rest (AES-256) and in transit (TLS 1.2+) |

---

## Core Zero Trust Patterns for Generated Code

### Pattern 1: Continuous Session Verification

**Why:** Traditional auth checks only at login. Zero Trust verifies on EVERY request.

**What to generate:**
```python
def verify_request(session_id: str, client_ip: str) -> bool:
    """
    Zero Trust Principle: Continuous Verification
    
    Every request must be verified, not just the initial login.
    This prevents session hijacking and ensures the same user/device
    is making the request throughout the session lifecycle.
    """
    session = get_session(session_id)
    if not session:
        return False
    
    # Check 1: Session not expired (15-min timeout per STIG V-220630)
    if session.is_expired():
        return False
    
    # Check 2: IP binding - same IP that created session
    # WHY: Prevents session token theft from being useful
    if session.ip_address != client_ip:
        audit_log("session_ip_mismatch", session.user_id, client_ip)
        return False
    
    # Check 3: Update last activity for timeout tracking
    session.touch()
    return True
```

### Pattern 2: Identity-Based Access Control

**Why:** Access decisions based on verified identity, not network location.

**What to generate:**
```python
def authorize_request(user_identity: dict, resource: str, action: str) -> bool:
    """
    Zero Trust Principle: Identity-Based Access
    
    Access is granted based on WHO you are (verified identity),
    not WHERE you are (network location). This is the core
    difference from perimeter security.
    
    Maps to: NIST AC-3 (Access Enforcement)
    """
    # Get user's verified identity attributes
    user_id = user_identity.get("user_id")
    roles = user_identity.get("roles", [])
    clearance = user_identity.get("clearance_level")
    
    # Check against resource policy (default deny)
    policy = get_resource_policy(resource)
    
    # Zero Trust: Default DENY, explicit ALLOW required
    if not policy:
        audit_log("access_denied_no_policy", user_id, resource)
        return False
    
    # Verify role-based access
    if not any(role in policy.allowed_roles for role in roles):
        audit_log("access_denied_insufficient_role", user_id, resource)
        return False
    
    return True
```

### Pattern 3: Session Regeneration After Authentication

**Why:** Prevents session fixation attacks where attacker sets session ID before login.

**What to generate:**
```python
def login_user(username: str, password: str, client_ip: str) -> dict:
    """
    Zero Trust Principle: Session Regeneration
    
    After successful authentication, generate a NEW session ID.
    This prevents session fixation attacks where an attacker
    tricks a user into using a known session ID.
    
    Maps to: STIG V-220630 (Session Management)
    """
    # Verify credentials
    user = authenticate(username, password)
    if not user:
        return {"success": False, "error": "Invalid credentials"}
    
    # CRITICAL: Generate new session ID after auth
    # WHY: Any pre-existing session ID could be attacker-controlled
    old_session = get_current_session()
    if old_session:
        destroy_session(old_session.id)
    
    # Create fresh session bound to this IP
    new_session = create_session(
        user_id=user.id,
        ip_address=client_ip,  # Bind to IP for Zero Trust
        created_at=datetime.utcnow()
    )
    
    audit_log("login_success", user.id, client_ip, {
        "session_id": new_session.id,
        "auth_method": "password"
    })
    
    return {"success": True, "session_id": new_session.id}
```

### Pattern 4: Least Privilege Access

**Why:** Users/services get minimum permissions needed, nothing more.

**What to generate:**
```python
def get_user_permissions(user_id: str, context: dict) -> list:
    """
    Zero Trust Principle: Least Privilege
    
    Grant only the minimum permissions required for the task.
    Permissions should be:
    - Scoped to specific resources
    - Time-bound when possible
    - Context-aware (location, device, time)
    
    Maps to: NIST AC-6 (Least Privilege)
    """
    base_permissions = get_role_permissions(user_id)
    
    # Apply context-based restrictions
    # WHY: Same user might have different access from different contexts
    if context.get("device_type") == "mobile":
        # Mobile devices get reduced permissions
        base_permissions = filter_mobile_allowed(base_permissions)
    
    if context.get("location") == "external":
        # External access gets reduced permissions
        base_permissions = filter_external_allowed(base_permissions)
    
    if context.get("time_outside_business_hours"):
        # After-hours access gets reduced permissions
        base_permissions = filter_after_hours_allowed(base_permissions)
    
    return base_permissions
```

### Pattern 5: Full Audit Trail

**Why:** Every action must be logged for compliance and forensic analysis.

**What to generate:**
```python
def audit_log(event_type: str, user_id: str, ip_address: str, details: dict = None):
    """
    Zero Trust Principle: Full Audit Trail
    
    Log EVERY security-relevant action with enough detail to:
    1. Reconstruct what happened (forensics)
    2. Prove compliance (auditors)
    3. Detect anomalies (SIEM integration)
    
    Maps to: NIST AU-2 (Audit Events), STIG V-220635
    
    Required fields per federal standards:
    - timestamp: When it happened (ISO 8601, UTC)
    - user_id: Who did it (or "anonymous" if unauthenticated)
    - ip_address: Where the request came from
    - action: What was attempted
    - outcome: Success or failure
    - details: Context-specific information
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "user_id": user_id or "anonymous",
        "ip_address": ip_address,
        "outcome": details.get("outcome", "success") if details else "success",
        "details": details or {},
        "correlation_id": get_correlation_id()  # For request tracing
    }
    
    # Write to immutable audit log
    # WHY: Audit logs must be tamper-evident for compliance
    write_audit_log(entry)
```

---

## Zero Trust vs Traditional Security

| Aspect | Traditional (Perimeter) | Zero Trust |
|--------|------------------------|------------|
| Trust model | Trust inside network | Trust nothing |
| Authentication | Once at login | Continuous |
| Authorization | Role-based only | Context + identity |
| Network | Flat, trusted | Micro-segmented |
| Default stance | Allow unless denied | Deny unless allowed |
| Logging | Selective | Everything |

---

## Implementation Checklist

When generating code, ensure:

- [ ] **No hardcoded trust** - Don't assume requests from "internal" IPs are safe
- [ ] **Session IP binding** - Bind session to originating IP
- [ ] **Session regeneration** - New session ID after login
- [ ] **15-minute timeout** - Sessions expire after inactivity (STIG V-220630)
- [ ] **Default deny** - No access without explicit grant
- [ ] **Full audit logging** - Log auth, access, and modifications
- [ ] **Input validation** - Validate ALL inputs (Zero Trust extends to data)
- [ ] **Encryption everywhere** - TLS in transit, AES-256 at rest

---

## Quick Reference: Zero Trust to NIST/STIG Mapping

| Zero Trust Principle | NIST Control | STIG Reference |
|---------------------|--------------|----------------|
| Continuous verification | AC-12 | V-220630 |
| Identity-based access | IA-2, AC-3 | V-220629 |
| Least privilege | AC-6 | V-220629 |
| Micro-segmentation | SC-7 | V-220640 |
| Encryption in transit | SC-8 | V-220634 |
| Encryption at rest | SC-28 | V-220633 |
| Full audit trail | AU-2, AU-3 | V-220635 |

---

## Important Note

**Devin is not FedRAMP certified.** This knowledge teaches Devin to generate code that follows Zero Trust principles and can be deployed in FedRAMP/federal environments. The generated code itself must be reviewed and deployed in an authorized environment (like Windsurf for FedRAMP High/IL5-IL6).

---

**Reference:** NIST SP 800-207 (Zero Trust Architecture)
