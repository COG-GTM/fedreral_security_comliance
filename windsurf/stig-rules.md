---
trigger: always_on
---

# STIG & NIST 800-53 Security Rules

> Copy this file to `.windsurf/rules/stig-rules.md` in your project.

## Authentication (STIG V-220629, NIST IA-2, IA-5)
- Password minimum 14 characters with complexity (upper, lower, digit, special)
- Hash passwords with bcrypt (12 rounds) or Argon2
- Implement MFA for privileged accounts
- Never store plaintext passwords

## Account Lockout (STIG V-220629, NIST AC-7)
- Lock after 5 failed login attempts
- 15-minute lockout duration
- Log all failed attempts with IP address

## Session Security (STIG V-220630, NIST AC-12)
- Session timeout: 15 minutes inactivity
- Secure cookie flags: Secure, HttpOnly, SameSite=Strict
- Regenerate session ID after login

## Input Validation (STIG V-220631, NIST SI-10)
- Validate ALL user inputs using whitelist approach
- Validate data types, formats, and ranges
- Enforce maximum length limits
- Reject unexpected input patterns

## Input Sanitization (STIG V-220632, NIST SI-10)
- Remove dangerous characters: < > " ' ; & | ` $ ( )
- Use parameterized queries for ALL database operations
- Encode output to prevent XSS
- Never execute user input in shell commands

## Encryption at Rest (STIG V-220633, NIST SC-28)
- Use AES-256 for sensitive data
- Store encryption keys securely (not in code)
- Rotate keys annually

## Encryption in Transit (STIG V-220634, NIST SC-8)
- TLS 1.2+ required for all communications
- Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1
- Valid certificates required

## Audit Logging (STIG V-220635, NIST AU-2, AU-3)
- Log: authentication attempts, data access, admin actions, security violations
- Format: JSON with timestamp, user_id, ip_address, action, outcome
- Never log passwords, tokens, or PII
- Retain logs minimum 1 year

## Security Headers (STIG V-220641, NIST SI-11)
All HTTP responses must include:
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy: default-src 'self'

## Error Handling (STIG V-220641, NIST SI-11)
- Return generic error messages to users
- Log detailed errors with context internally
- Never expose stack traces to users
- Use appropriate HTTP status codes

## Secrets Management
- Never hardcode secrets, API keys, or credentials
- Use environment variables or secret managers
- Add sensitive files to .gitignore
- Rotate secrets regularly

## Code Patterns

### Python Input Validation
```python
import re
from typing import Optional

def validate_and_sanitize(value: str, max_length: int = 255) -> Optional[str]:
    if not value or len(value) > max_length:
        return None
    sanitized = re.sub(r'[<>"\';&|`$()]', '', value.strip())
    return sanitized if sanitized else None
```

### Python Password Hashing
```python
import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
```

### Flask Security Headers
```python
@app.after_request
def security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### Parameterized Query
```python
# CORRECT
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# WRONG - SQL injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```
