# Federal Security Compliance Framework

> Centralized STIG & NIST 800-53 compliance for federal systems development with Devin and Windsurf.

## Quick Start

### For Devin Users
1. Copy `devin/knowledge.md` → Devin Knowledge
2. Copy `devin/playbook.md` → Devin Playbooks
3. Done! All code will follow federal security standards.

### For Windsurf Users
1. Copy `windsurf/stig-rules.md` → `.windsurf/rules/stig-rules.md`
2. Done! Cascade will enforce compliance automatically.

## What's Included

| File | Purpose |
|------|---------|
| `devin/knowledge.md` | Security knowledge for Devin |
| `devin/playbook.md` | Secure development workflow for Devin |
| `windsurf/stig-rules.md` | STIG rules for Windsurf Cascade |
| `templates/python/` | Reusable secure Python modules |

## Compliance Coverage

- **STIG** - All 18 security categories
- **NIST 800-53** - AC, AU, IA, SC, SI control families
- **FedRAMP** - Moderate baseline
- **Federal Software Engineering Standards** - General compliance requirements

## Key Security Controls

| Control | Implementation |
|---------|----------------|
| Input Validation | Whitelist validation, sanitization |
| Authentication | 14+ char passwords, MFA, account lockout |
| Session Security | 15 min timeout, secure cookies |
| Encryption | AES-256 at rest, TLS 1.2+ in transit |
| Audit Logging | JSON format, all security events |
| Security Headers | HSTS, CSP, X-Frame-Options |

## Templates

### Python Security Modules
- `security_utils.py` - Input validation, sanitization, rate limiting
- `auth_manager.py` - Authentication, sessions, password policies
- `audit_logger.py` - Structured audit logging

## Usage Example

```python
# Import from templates
from security_utils import InputValidator, InputSanitizer

# Validate user input (STIG V-220631)
if not InputValidator.validate_email(user_email):
    return error("Invalid email")

# Sanitize input (STIG V-220632)
safe_input = InputSanitizer.sanitize_string(user_input)
```

## License

For use in US Government and authorized contractor systems.

---

**Classification: UNCLASSIFIED**