# Zero Trust Architecture Guide

## Overview

This document explains the Zero Trust Architecture (ZTA) implementation in this repository and how it maps to federal security requirements. It is intended for developers, security engineers, and compliance officers.

---

## What is Zero Trust Architecture?

**Zero Trust** is a security model that eliminates implicit trust in any network, user, or device. The core principle:

> **"Never trust, always verify"**

### Traditional vs Zero Trust Security

| Aspect | Traditional (Perimeter) | Zero Trust |
|--------|-------------------------|------------|
| **Trust Model** | Trust everything inside the firewall | Trust nothing, verify everything |
| **Authentication** | Once at the perimeter | Continuous, every request |
| **Authorization** | Broad access based on network location | Granular, identity-based, context-aware |
| **Network** | Flat internal network | Micro-segmented |
| **Default Stance** | Allow unless explicitly denied | Deny unless explicitly allowed |
| **Monitoring** | Perimeter-focused | Universal, all traffic |

### Why Zero Trust Matters for Federal Systems

1. **Perimeter is obsolete** - Cloud, mobile, and remote work dissolved the network edge
2. **Insider threats** - 34% of breaches involve internal actors (Verizon DBIR)
3. **Lateral movement** - Once inside, attackers move freely in traditional networks
4. **Compliance** - Executive Order 14028 mandates Zero Trust for federal agencies

---

## The Five Pillars of Zero Trust

Zero Trust is built on five interconnected pillars, each requiring specific implementation:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ZERO TRUST ARCHITECTURE                          │
├─────────────┬─────────────┬─────────────┬─────────────┬────────────────┤
│  IDENTITY   │   DEVICE    │   NETWORK   │ APPLICATION │     DATA       │
├─────────────┼─────────────┼─────────────┼─────────────┼────────────────┤
│ Who is the  │ What device │ Is network  │ Is app      │ Is data        │
│ user?       │ is this?    │ segmented?  │ secure?     │ protected?     │
├─────────────┼─────────────┼─────────────┼─────────────┼────────────────┤
│ CAC/PIV     │ Cert-based  │ Micro-      │ Input       │ AES-256        │
│ SAML/OIDC   │ MDM         │ segmentation│ validation  │ TLS 1.2+       │
│ MFA         │ Posture     │ Zero trust  │ Auth on     │ Access         │
│             │ check       │ network     │ every API   │ controls       │
└─────────────┴─────────────┴─────────────┴─────────────┴────────────────┘
```

### Pillar 1: Identity

**Principle:** Verify every user's identity before granting any access.

**Implementation in this repo:**
- `auth_manager.py` - Authentication with password policy
- `cac_piv_handler.py` - CAC/PIV certificate authentication
- Strong password requirements (14+ chars, complexity)
- Account lockout after 5 failed attempts

**Federal Mapping:** NIST IA-2, IA-5, STIG V-220629

### Pillar 2: Device

**Principle:** Verify the device making the request is trusted.

**Implementation in this repo:**
- `cac_piv_handler.py` - X.509 client certificate validation
- Device identity via certificate fingerprint
- Session binding to device characteristics

**Federal Mapping:** NIST IA-3, CM-8

### Pillar 3: Network

**Principle:** Don't trust network location. Segment and isolate.

**Implementation considerations:**
- Encrypt all traffic (TLS 1.2+ mandatory)
- No implicit trust for "internal" networks
- Micro-segmentation at application level

**Federal Mapping:** NIST SC-7, SC-8

### Pillar 4: Application

**Principle:** Secure every application. Authenticate every API call.

**Implementation in this repo:**
- `zero_trust_middleware.py` - Request authentication
- `security_utils.py` - Input validation/sanitization
- Security headers on all responses
- Generic error messages (no information leakage)

**Federal Mapping:** NIST AC-3, SI-10, SI-11

### Pillar 5: Data

**Principle:** Protect data everywhere - at rest and in transit.

**Implementation in this repo:**
- AES-256 encryption at rest (documented requirement)
- TLS 1.2+ in transit (mandatory)
- Access logging for all data operations

**Federal Mapping:** NIST SC-8, SC-28, STIG V-220633, V-220634

---

## Zero Trust Implementation Flow

This diagram shows how a request flows through Zero Trust controls:

```
┌──────────────┐
│   Client     │
│ (User + CAC) │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        TLS TERMINATION                                │
│  • Verify client certificate (CAC/PIV)                               │
│  • Extract identity from cert DN                                      │
│  • Pass identity to application via headers                          │
└──────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    CONTINUOUS VERIFICATION                            │
│  1. Session exists?                    → If no: REJECT (401)         │
│  2. Session expired? (15-min timeout)  → If yes: REJECT (401)        │
│  3. IP matches session binding?        → If no: REJECT + LOG ALERT   │
│  4. User account active?               → If no: REJECT (401)         │
└──────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    AUTHORIZATION (Least Privilege)                    │
│  1. Does user have permission for this resource?                     │
│  2. Does context allow? (time, location, device)                     │
│  3. DEFAULT IS DENY - must have explicit grant                       │
└──────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    INPUT VALIDATION                                   │
│  • Validate format (whitelist approach)                              │
│  • Sanitize (remove dangerous characters)                            │
│  • Reject invalid input BEFORE processing                            │
└──────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    BUSINESS LOGIC                                     │
│  (Your application code)                                             │
└──────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    AUDIT LOGGING                                      │
│  • Log: who, what, when, where, outcome                              │
│  • Structured JSON format for SIEM                                   │
│  • Immutable storage                                                 │
└──────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    RESPONSE + SECURITY HEADERS                        │
│  • Add HSTS, CSP, X-Frame-Options, etc.                              │
│  • Generic error messages (no info leakage)                          │
│  • Proper HTTP status codes                                          │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Key Implementation Details

### 1. IP-Bound Sessions

**What:** Each session is bound to the IP address that created it.

**Why:** If an attacker steals a session token but tries to use it from a different IP, the session is rejected. This significantly raises the bar for session hijacking attacks.

**Code:**
```python
def validate_session(session_id, request_ip):
    session = get_session(session_id)
    if session.bound_ip != request_ip:
        log_security_event("session_ip_mismatch", ...)
        destroy_session(session_id)  # Critical: destroy, not just reject
        return None
    return session
```

**Trade-off:** Users on networks with changing IPs (some mobile networks) may need to re-authenticate more often. This is acceptable for security.

### 2. Session Regeneration

**What:** After successful authentication, generate a completely new session ID.

**Why:** Prevents session fixation attacks where an attacker pre-sets a known session ID and waits for the victim to authenticate.

**Code:**
```python
def login(username, password, request_ip):
    user = authenticate(username, password)
    
    # Destroy any existing session (prevents fixation)
    destroy_existing_sessions(user.id)
    
    # Create NEW session with NEW ID
    new_session = create_session(user.id, request_ip)
    return new_session
```

### 3. 15-Minute Session Timeout

**What:** Sessions expire after 15 minutes of inactivity.

**Why:** Federal requirement (STIG V-220630). Limits the window for session-based attacks.

**Code:**
```python
SESSION_TIMEOUT_MINUTES = 15  # Do not change without security review

def is_session_expired(session):
    inactive_time = datetime.utcnow() - session.last_activity
    return inactive_time > timedelta(minutes=SESSION_TIMEOUT_MINUTES)
```

### 4. Continuous Verification

**What:** Verify identity on EVERY request, not just at login.

**Why:** Sessions can be stolen, users can be deactivated, context can change. Only continuous verification catches these scenarios.

**Code:**
```python
@app.before_request
def verify_every_request():
    if request.path in PUBLIC_ENDPOINTS:
        return  # Skip for truly public endpoints
    
    session = validate_session(request.cookies.get('session_id'), request.remote_addr)
    if not session:
        return jsonify({"error": "Authentication required"}), 401
```

---

## Federal Compliance Mapping

### NIST SP 800-207 (Zero Trust Architecture)

| 800-207 Section | This Repository |
|-----------------|-----------------|
| 3.1 Variations of ZTA | Identity-centric approach |
| 3.2 Trust Algorithm | IP binding + session validity + authorization |
| 4.1 Network-Based | Not reliant on network location |
| 4.2 Identity-Based | CAC/PIV, strong passwords |

### NIST SP 800-53 Rev 5 (Security Controls)

| Control | Implementation |
|---------|----------------|
| AC-2 (Account Management) | `auth_manager.py` |
| AC-3 (Access Enforcement) | Authorization checks |
| AC-6 (Least Privilege) | Default deny, explicit grants |
| AC-7 (Unsuccessful Logins) | Account lockout (5 attempts) |
| AC-12 (Session Termination) | 15-minute timeout |
| AU-2 (Audit Events) | `audit_logger.py` |
| AU-3 (Content of Audit Records) | Structured JSON logs |
| IA-2 (Identification and Authentication) | CAC/PIV, passwords |
| IA-5 (Authenticator Management) | Password policy |
| SC-8 (Transmission Confidentiality) | TLS 1.2+ required |
| SC-28 (Protection of Information at Rest) | AES-256 |
| SI-10 (Information Input Validation) | `security_utils.py` |
| SI-11 (Error Handling) | Generic errors, detailed logging |

### STIG Mapping

| STIG ID | Title | Implementation |
|---------|-------|----------------|
| V-220629 | Authentication | `auth_manager.py`, `cac_piv_handler.py` |
| V-220630 | Session Management | `zero_trust_middleware.py` |
| V-220631 | Input Validation | `security_utils.py` InputValidator |
| V-220632 | Input Sanitization | `security_utils.py` InputSanitizer |
| V-220633 | Encryption at Rest | AES-256 requirement |
| V-220634 | Encryption in Transit | TLS 1.2+ requirement |
| V-220635 | Audit Logging | `audit_logger.py` |
| V-220641 | Error Handling | Security headers, generic errors |

---

## Deployment Considerations

### For FedRAMP Environments (Windsurf)

Windsurf is FedRAMP High authorized and IL5-IL6 certified. When deploying in Windsurf:

1. **Use all Zero Trust controls** - They are mandatory, not optional
2. **Enable CAC/PIV authentication** - Required for DoD systems
3. **Configure proper logging** - Logs must be retained for 1+ year
4. **Review security headers** - CSP should be tightened for production

### For Development/Testing (Devin)

Devin is NOT FedRAMP certified. When using Devin for development:

1. **Generate Zero Trust compliant code** - Use patterns from this repo
2. **Test security controls** - Run `tests/test_zero_trust.py`
3. **Deploy to authorized environment** - Production must be FedRAMP authorized

---

## Testing Zero Trust Implementation

Run the test suite to verify Zero Trust controls:

```bash
# Run all Zero Trust tests
pytest tests/test_zero_trust.py -v

# Run with coverage
pytest tests/test_zero_trust.py -v --cov=templates/python

# Run specific test class
pytest tests/test_zero_trust.py::TestIPBoundSessions -v
```

### What Tests Verify

| Test Class | Zero Trust Principle |
|------------|---------------------|
| `TestIPBoundSessions` | Sessions bound to IP |
| `TestSessionTimeout` | 15-minute expiration |
| `TestSessionRegeneration` | New ID after auth |
| `TestContinuousVerification` | Every request verified |
| `TestAuditLogging` | Security events logged |

---

## References

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [NIST SP 800-53 Rev 5: Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)
- [DoD Zero Trust Reference Architecture](https://dodcio.defense.gov/Portals/0/Documents/Library/DoD-ZTStrategy.pdf)
- [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)

---

**Classification: UNCLASSIFIED**
