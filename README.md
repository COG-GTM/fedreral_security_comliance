# Federal Security Compliance Framework

> Centralized STIG, NIST 800-53, and Zero Trust compliance for federal systems development with Devin and Windsurf.

## Platform Authorization Status

| Platform | FedRAMP Status | IL Level | Use Case |
|----------|----------------|----------|----------|
| **Windsurf** | FedRAMP High Authorized | IL5-IL6 | Production federal systems |
| **Devin** | Not FedRAMP Certified | N/A | Generate compliant code patterns |

## Quick Start

### For Devin Users
1. Copy `devin/knowledge.md` → Devin Knowledge
2. Copy `devin/playbook.md` → Devin Playbooks
3. Copy `devin/zero-trust-knowledge.md` → Devin Knowledge (Zero Trust)
4. Copy `devin/zero-trust-playbook.md` → Devin Playbooks (Zero Trust)
5. Done! Devin will generate Zero Trust compliant code.

### For Windsurf Users
1. Copy `windsurf/stig-rules.md` → `.windsurf/rules/stig-rules.md`
2. Copy `windsurf/zero-trust-rules.md` → `.windsurf/rules/zero-trust-rules.md`
3. Done! Cascade will enforce Zero Trust compliance automatically.

## What's Included

| File | Purpose |
|------|---------|
| `devin/knowledge.md` | Security knowledge for Devin |
| `devin/playbook.md` | Secure development workflow for Devin |
| `devin/zero-trust-knowledge.md` | Zero Trust principles for Devin |
| `devin/zero-trust-playbook.md` | Zero Trust workflow for Devin |
| `windsurf/stig-rules.md` | STIG rules for Windsurf Cascade |
| `windsurf/zero-trust-rules.md` | Zero Trust rules for Windsurf (FedRAMP context) |
| `templates/python/` | Reusable secure Python modules |
| `tests/` | Automated compliance verification tests |
| `docs/` | Architecture and compliance documentation |

## Compliance Coverage

- **Zero Trust Architecture** - NIST SP 800-207 implementation
- **STIG** - All 18 security categories
- **NIST 800-53** - AC, AU, IA, SC, SI control families
- **FedRAMP** - Moderate and High baseline
- **Federal Software Engineering Standards** - General compliance requirements

## Zero Trust Architecture

This framework implements **NIST SP 800-207 Zero Trust Architecture** principles:

| Principle | Implementation | Why It Matters |
|-----------|----------------|----------------|
| **Never Trust, Always Verify** | Continuous session verification | Tokens can be stolen mid-session |
| **IP-Bound Sessions** | Sessions tied to originating IP | Stolen tokens useless from different IP |
| **Session Regeneration** | New session ID after auth | Prevents session fixation attacks |
| **15-Minute Timeout** | Sessions expire per STIG V-220630 | Limits attack window |
| **Least Privilege** | Default deny, explicit grants | Limits blast radius of compromise |
| **Full Audit Trail** | Every action logged | Forensics and compliance |

### Zero Trust Flow

```
Request → Verify Session → Check IP Binding → Check Timeout → Authorize → Process → Log
            ↓                    ↓                 ↓              ↓
         Missing?            Mismatch?          Expired?       Denied?
            ↓                    ↓                 ↓              ↓
         REJECT              DESTROY +          REJECT         REJECT
                             LOG ALERT
```

## Key Security Controls

| Control | Implementation | Federal Mapping |
|---------|----------------|-----------------|
| Input Validation | Whitelist validation, sanitization | STIG V-220631, NIST SI-10 |
| Authentication | 14+ char passwords, MFA, CAC/PIV | STIG V-220629, NIST IA-2 |
| Session Security | 15 min timeout, IP binding | STIG V-220630, NIST AC-12 |
| Encryption | AES-256 at rest, TLS 1.2+ in transit | STIG V-220633/34, NIST SC-8/28 |
| Audit Logging | JSON format, all security events | STIG V-220635, NIST AU-2/3 |
| Security Headers | HSTS, CSP, X-Frame-Options | STIG V-220641, NIST SI-11 |

## Templates

### Python Security Modules
- `security_utils.py` - Input validation, sanitization, rate limiting
- `auth_manager.py` - Authentication, sessions, password policies
- `audit_logger.py` - Structured audit logging
- `zero_trust_middleware.py` - IP binding, continuous verification, session management
- `cac_piv_handler.py` - CAC/PIV certificate authentication for DoD systems

## Testing

Run the compliance test suite:

```bash
# Run all Zero Trust tests
pytest tests/test_zero_trust.py -v

# Run with coverage
pytest tests/ -v --cov=templates/python
```

### What Tests Verify

| Test | Zero Trust Principle |
|------|---------------------|
| `TestIPBoundSessions` | Sessions reject requests from different IPs |
| `TestSessionTimeout` | Sessions expire after 15 minutes |
| `TestSessionRegeneration` | New session ID generated after login |
| `TestContinuousVerification` | Every request must have valid session |
| `TestAuditLogging` | Security events are properly logged |

## Usage Example

```python
# Import Zero Trust middleware
from zero_trust_middleware import (
    create_zero_trust_session,
    validate_session,
    zero_trust_required
)

# Create IP-bound session after authentication
session = create_zero_trust_session(
    user_id=user.id,
    ip_address=request.remote_addr,
    user_agent=request.headers.get('User-Agent')
)

# Protect endpoints with Zero Trust decorator
@app.route('/api/sensitive-data')
@zero_trust_required  # Enforces continuous verification
def get_sensitive_data():
    user_id = g.current_user  # Verified identity
    # ... your code
```

## Documentation

- `docs/zero-trust-architecture.md` - Full Zero Trust implementation guide
- Federal compliance mapping (NIST, STIG, FedRAMP)
- Architecture diagrams and flow charts

## License

For use in US Government and authorized contractor systems.

---

**Classification: UNCLASSIFIED**