# Federal Security Compliance Knowledge

> Copy this entire file to your Devin Knowledge base.

## Overview

All code must comply with STIG and NIST 800-53 security standards. This knowledge ensures secure coding practices for federal systems.

---

## Core Security Rules

### 1. Input Validation (STIG V-220631)
**Always validate ALL user inputs using whitelist approach:**
- Validate email format with regex
- Validate numeric ranges
- Enforce length limits (max 255 chars default)
- Reject unknown/unexpected input patterns

```python
# Example: Validate before processing
if not re.match(r'^[a-zA-Z0-9_-]+$', username):
    return error("Invalid username format")
```

### 2. Input Sanitization (STIG V-220632)
**Remove dangerous characters to prevent injection:**
- Remove: `< > " ' ; & | $ ( ) \` `
- Use parameterized queries for databases
- Encode output to prevent XSS

```python
# Example: Sanitize user input
sanitized = re.sub(r'[<>"\';&|`$()]', '', user_input.strip())
```

### 3. Authentication (STIG V-220629)
**Password requirements:**
- Minimum 14 characters
- Must include: uppercase, lowercase, digit, special character
- Hash with bcrypt (12 rounds minimum)
- Never store plaintext passwords

```python
# Example: Hash password
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

### 4. Account Lockout (STIG V-220629)
- Lock account after 5 failed login attempts
- 15-minute lockout duration
- Log all failed attempts

### 5. Session Security (STIG V-220630)
- Session timeout: 15 minutes inactivity
- Secure cookie flags: `Secure`, `HttpOnly`, `SameSite=Strict`
- Regenerate session ID after login

### 6. Encryption (STIG V-220633, V-220634)
- **At rest:** AES-256
- **In transit:** TLS 1.2+ only
- **Never hardcode secrets** - use environment variables

### 7. Audit Logging (STIG V-220635)
**Log these events in JSON format:**
- Authentication (success/failure)
- Authorization failures
- Data access/modification
- Admin actions

```python
# Example: Audit log entry
{
    "timestamp": "2026-01-11T19:30:00Z",
    "event": "authentication_failure",
    "user": "john.doe",
    "ip": "192.168.1.1",
    "reason": "invalid_password"
}
```

### 8. Security Headers (STIG V-220641)
**Every HTTP response must include:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
```

### 9. Error Handling (STIG V-220641)
- Return generic messages to users: "An error occurred"
- Log detailed errors internally with stack traces
- Never expose internal details to users

---

## STIG ↔ NIST Quick Reference

| STIG | NIST | What to Implement |
|------|------|-------------------|
| V-220629 | IA-2, IA-5 | MFA, password policy, bcrypt |
| V-220630 | AC-7, AC-12 | Lockout (5 attempts), timeout (15 min) |
| V-220631 | SI-10 | Whitelist input validation |
| V-220632 | SI-10 | Parameterized queries, sanitization |
| V-220633 | SC-28 | AES-256 encryption at rest |
| V-220634 | SC-8 | TLS 1.2+ in transit |
| V-220635 | AU-2, AU-3 | JSON audit logging |
| V-220641 | SI-11 | Security headers, generic errors |

---

## Code Patterns

### Secure Flask Route
```python
@app.route("/api/data", methods=["POST"])
def handle_data():
    # 1. Get client IP for logging
    client_ip = request.remote_addr
    
    # 2. Validate input
    data = request.get_json()
    if not data or 'field' not in data:
        log_security_event("validation_failure", client_ip)
        return jsonify({"error": "Invalid request"}), 400
    
    # 3. Sanitize input
    safe_field = sanitize_string(data['field'])
    if not safe_field:
        return jsonify({"error": "Invalid data"}), 400
    
    # 4. Process and log
    log_security_event("data_access", client_ip, {"action": "read"})
    return jsonify({"status": "ok"})
```

### Secure Database Query
```python
# CORRECT - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# WRONG - SQL injection vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

---

## Checklist

Before completing any code task:
- [ ] All user inputs validated (whitelist)
- [ ] All user inputs sanitized
- [ ] No hardcoded secrets
- [ ] Parameterized database queries
- [ ] Security events logged
- [ ] Generic error messages to users
- [ ] Security headers on responses

---

**Reference:** https://github.com/COG-GTM/fedreral_security_comliance
