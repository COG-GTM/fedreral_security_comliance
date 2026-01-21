---
trigger: always_on
---

# Zero Trust Architecture Rules for Windsurf

> Copy this file to `.windsurf/rules/zero-trust-rules.md` in your project.

## About This Document

**Windsurf is FedRAMP High Authorized and IL5-IL6 certified.** This means code developed in Windsurf can be deployed in federal environments including DoD systems. These rules ensure generated code follows Zero Trust Architecture as defined by NIST SP 800-207 and meets federal security requirements.

---

## What is Zero Trust?

Zero Trust is a security model that eliminates implicit trust. The core principle:

> **"Never trust, always verify"**

Every user, device, and network flow must be authenticated and authorized at each step. There is no trusted network perimeter - threats can exist anywhere.

---

## Zero Trust Principles → Code Requirements

### Principle 1: Continuous Verification

**What it means:** Don't just verify at login. Verify on EVERY request.

**Why it matters:** Session tokens can be stolen. Network positions can be spoofed. Only continuous verification catches these attacks.

**Code requirement:**
```python
@app.before_request
def zero_trust_verify():
    """
    Zero Trust: Verify identity on EVERY request
    
    This runs before any endpoint handler. If verification fails,
    the request is rejected before reaching application logic.
    
    Federal Mapping: NIST AC-12, STIG V-220630
    """
    # Skip public endpoints (health checks, login page)
    if request.path in PUBLIC_ENDPOINTS:
        return None
    
    session_id = request.cookies.get('session_id')
    if not session_id:
        return jsonify({"error": "Authentication required"}), 401
    
    # Validate session with IP binding check
    session = validate_session_with_ip_binding(session_id, request.remote_addr)
    if not session:
        return jsonify({"error": "Session invalid"}), 401
    
    # Attach verified identity for downstream use
    g.current_user = session.user_id
    g.session = session
```

---

### Principle 2: IP-Bound Sessions

**What it means:** Tie each session to the IP address that created it.

**Why it matters:** If an attacker steals a session token but doesn't control the victim's IP, the token is useless. This is a critical defense against session hijacking.

**Code requirement:**
```python
def validate_session_with_ip_binding(session_id: str, request_ip: str) -> Optional[Session]:
    """
    Zero Trust: Sessions are bound to IP addresses
    
    If the request comes from a different IP than the session was created with,
    we assume the session was stolen and invalidate it.
    
    Federal Mapping: STIG V-220630 (Session Management)
    
    WHY THIS WORKS:
    - Attacker steals session token via XSS or network sniffing
    - Attacker tries to use token from their own IP
    - IP doesn't match → session rejected
    - Attack fails
    """
    session = session_store.get(session_id)
    if not session:
        return None
    
    # Check timeout (15 minutes per federal requirements)
    if session.is_expired():
        session_store.delete(session_id)
        audit_log("session_expired", session.user_id, request_ip)
        return None
    
    # CRITICAL: IP binding check
    if session.bound_ip != request_ip:
        audit_log("session_ip_mismatch", session.user_id, request_ip, {
            "bound_ip": session.bound_ip,
            "request_ip": request_ip,
            "threat_indicator": "possible_session_hijacking"
        })
        session_store.delete(session_id)  # Invalidate compromised session
        return None
    
    # Update activity timestamp (sliding window)
    session.last_activity = datetime.utcnow()
    session_store.update(session)
    
    return session
```

---

### Principle 3: Session Regeneration After Authentication

**What it means:** After a user logs in, create a completely new session ID.

**Why it matters:** Prevents session fixation attacks where an attacker plants a known session ID and waits for the victim to authenticate with it.

**Code requirement:**
```python
def login(username: str, password: str, request_ip: str) -> dict:
    """
    Zero Trust: Regenerate session after authentication
    
    ATTACK SCENARIO (Session Fixation):
    1. Attacker visits site, gets session ID "abc123"
    2. Attacker tricks victim into using session ID "abc123"
    3. Victim logs in with session "abc123"
    4. Attacker now has authenticated session "abc123"
    
    DEFENSE:
    After successful auth, generate NEW session ID.
    Attacker's known session ID becomes useless.
    
    Federal Mapping: STIG V-220630, OWASP Session Management
    """
    # Authenticate user
    user = authenticate_credentials(username, password)
    if not user:
        return {"success": False}
    
    # CRITICAL: Destroy any pre-existing session
    old_session_id = request.cookies.get('session_id')
    if old_session_id:
        session_store.delete(old_session_id)
    
    # Create fresh session with new ID
    new_session = Session(
        session_id=secrets.token_urlsafe(32),  # NEW cryptographic ID
        user_id=user.id,
        bound_ip=request_ip,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=15)
    )
    session_store.create(new_session)
    
    audit_log("login_success", user.id, request_ip, {
        "new_session_id": new_session.session_id
    })
    
    return {"success": True, "session_id": new_session.session_id}
```

---

### Principle 4: Least Privilege Access

**What it means:** Users and services get only the minimum permissions required.

**Why it matters:** If an account is compromised, damage is limited to what that account can access. Default-deny ensures no accidental over-permissioning.

**Code requirement:**
```python
def authorize(user_id: str, resource: str, action: str) -> bool:
    """
    Zero Trust: Least Privilege Authorization
    
    DEFAULT IS DENY. Access is only granted if:
    1. User has explicit permission for resource:action
    2. No deny rule overrides
    3. Context allows (time, location, device)
    
    Federal Mapping: NIST AC-6 (Least Privilege), AC-3 (Access Enforcement)
    
    PRINCIPLE:
    - Don't ask "is this user blocked?"
    - Ask "is this user explicitly allowed?"
    - If not explicitly allowed → DENY
    """
    # Get user's explicit permissions
    permissions = get_user_permissions(user_id)
    required = f"{resource}:{action}"
    
    # Default DENY - must have explicit grant
    if required not in permissions:
        audit_log("access_denied", user_id, request.remote_addr, {
            "resource": resource,
            "action": action,
            "reason": "no_explicit_permission"
        })
        return False
    
    audit_log("access_granted", user_id, request.remote_addr, {
        "resource": resource,
        "action": action
    })
    return True
```

---

### Principle 5: Full Audit Trail

**What it means:** Log every security-relevant action with full context.

**Why it matters:** Required for federal compliance (FedRAMP, FISMA). Enables incident response, forensics, and compliance audits.

**Code requirement:**
```python
def audit_log(event: str, user_id: str, ip: str, details: dict = None):
    """
    Zero Trust: Comprehensive Audit Logging
    
    Every security event must be logged with enough detail to:
    - Reconstruct what happened (incident response)
    - Prove compliance (auditors)
    - Detect patterns (SIEM/analytics)
    
    Federal Mapping: 
    - NIST AU-2 (Audit Events): Defines what to log
    - NIST AU-3 (Content of Audit Records): Defines log fields
    - STIG V-220635: Implementation requirements
    
    REQUIRED FIELDS (per AU-3):
    - Timestamp (when)
    - User identity (who)
    - Event type (what)
    - Outcome (success/failure)
    - Source (where/IP)
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event,
        "user_id": user_id or "anonymous",
        "ip_address": ip,
        "outcome": "failure" if "denied" in event or "failed" in event else "success",
        "details": details or {},
        "correlation_id": g.get("correlation_id", str(uuid.uuid4()))
    }
    
    logger.info(json.dumps(entry))
```

**Events that MUST be logged:**

| Event | Trigger | Federal Requirement |
|-------|---------|---------------------|
| `login_success` | User authenticates | AU-2(a)(1) |
| `login_failed` | Auth fails | AU-2(a)(1) |
| `logout` | User logs out | AU-2(a)(1) |
| `session_expired` | Timeout reached | AU-2(a)(2) |
| `session_ip_mismatch` | IP binding violated | AU-2(a)(3) |
| `access_granted` | Authorization succeeds | AU-2(a)(4) |
| `access_denied` | Authorization fails | AU-2(a)(4) |
| `data_read` | Data accessed | AU-2(a)(7) |
| `data_modified` | Data changed | AU-2(a)(7) |
| `admin_action` | Privileged operation | AU-2(a)(5) |

---

### Principle 6: Identity-Based Access Control

**What it means:** Access decisions based on verified identity, not network location.

**Why it matters:** In Zero Trust, being "inside the network" grants no privileges. Only verified identity matters.

**Code requirement for CAC/PIV integration:**
```python
def extract_cac_identity(request) -> Optional[dict]:
    """
    Zero Trust: Identity-Based Access via CAC/PIV
    
    DoD environments use CAC (Common Access Card) or PIV (Personal Identity
    Verification) smart cards for strong identity verification.
    
    HOW IT WORKS:
    1. User presents CAC to card reader
    2. TLS client certificate authentication at load balancer
    3. Load balancer extracts cert info, passes to app via headers
    4. App validates identity against user store
    
    Federal Mapping: NIST IA-2 (Multi-Factor Auth), FIPS 201 (PIV)
    
    NOTE: TLS termination happens at reverse proxy (nginx/Apache).
    Application receives identity via headers.
    """
    # Headers set by TLS-terminating reverse proxy
    client_dn = request.headers.get('X-SSL-Client-DN')
    client_cert_verify = request.headers.get('X-SSL-Client-Verify')
    
    if client_cert_verify != 'SUCCESS':
        return None
    
    if not client_dn:
        return None
    
    # Parse DoD CAC DN format: CN=LASTNAME.FIRSTNAME.MI.EDIPI
    import re
    match = re.search(r'CN=([^,]+)', client_dn)
    if not match:
        return None
    
    cn = match.group(1)
    parts = cn.split('.')
    
    if len(parts) >= 4:
        return {
            "cn": cn,
            "last_name": parts[0],
            "first_name": parts[1],
            "edipi": parts[-1],  # DoD ID number
            "auth_method": "CAC"
        }
    
    return None
```

---

## Security Headers (All Responses)

**Why:** Defense in depth. Even if application code has vulnerabilities, headers provide additional protection.

```python
@app.after_request
def add_security_headers(response):
    """
    Zero Trust extends to browser security
    
    These headers protect against common web attacks even
    if application code has vulnerabilities.
    
    Federal Mapping: STIG V-220641
    """
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS filter
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Force HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content Security Policy - restrict resource loading
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    
    return response
```

---

## 15-Minute Session Timeout

**Why:** Federal requirement. Limits window for session-based attacks.

```python
SESSION_TIMEOUT_MINUTES = 15  # STIG V-220630 requirement

def is_session_expired(session: Session) -> bool:
    """
    Zero Trust: Enforce session timeout
    
    Sessions MUST expire after 15 minutes of inactivity.
    This is a federal requirement, not a suggestion.
    
    WHY 15 MINUTES:
    - Balances security vs usability
    - Limits attack window for stolen sessions
    - Required by STIG V-220630
    """
    if datetime.utcnow() > session.expires_at:
        return True
    
    # Also check inactivity
    inactive_duration = datetime.utcnow() - session.last_activity
    if inactive_duration > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        return True
    
    return False
```

---

## Zero Trust Checklist for Code Review

Before approving any code:

- [ ] **Authentication** - Every endpoint requires verified identity (except explicit public endpoints)
- [ ] **Session IP Binding** - Sessions bound to creating IP, validated on each request
- [ ] **Session Regeneration** - New session ID generated after authentication
- [ ] **15-Minute Timeout** - Sessions expire after 15 minutes inactivity
- [ ] **Least Privilege** - Default deny, explicit grants only
- [ ] **Audit Logging** - All security events logged with required fields
- [ ] **Security Headers** - All responses include HSTS, CSP, X-Frame-Options
- [ ] **Generic Errors** - No internal details leaked in error messages
- [ ] **Input Validation** - All inputs validated and sanitized

---

## Federal Compliance Mapping

| Zero Trust Principle | NIST Control | FedRAMP Baseline | STIG |
|---------------------|--------------|------------------|------|
| Continuous verification | AC-12 | Moderate, High | V-220630 |
| Identity-based access | IA-2 | Moderate, High | V-220629 |
| Least privilege | AC-6 | Moderate, High | V-220629 |
| Session management | AC-12 | Moderate, High | V-220630 |
| Audit logging | AU-2, AU-3 | Moderate, High | V-220635 |
| Encryption in transit | SC-8 | Moderate, High | V-220634 |

---

**Reference:** NIST SP 800-207 (Zero Trust Architecture), NIST SP 800-53 Rev 5
