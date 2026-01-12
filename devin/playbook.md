# Secure Development Playbook

> Copy this entire file to your Devin Playbooks.

## When to Apply
**Always** - Apply this playbook to all code generation and modification tasks.

---

## Step 1: Before Writing Code

Check if the task involves:
- [ ] User input handling → Apply input validation
- [ ] Authentication → Apply password/session rules
- [ ] Database queries → Use parameterized queries
- [ ] API endpoints → Add security headers
- [ ] Sensitive data → Apply encryption

---

## Step 2: Input Handling

**For ANY user input:**

```python
# 1. Validate format (whitelist approach)
import re

def validate_input(value: str, pattern: str, max_length: int = 255) -> bool:
    if not value or len(value) > max_length:
        return False
    return bool(re.match(pattern, value))

# 2. Sanitize (remove dangerous chars)
def sanitize(value: str) -> str:
    return re.sub(r'[<>"\';&|`$()]', '', value.strip())

# 3. Use both
if not validate_input(user_email, r'^[\w.+-]+@[\w.-]+\.\w{2,}$'):
    return error("Invalid email")
safe_email = sanitize(user_email)
```

---

## Step 3: Authentication Code

**Password hashing:**
```python
import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())
```

**Account lockout:**
```python
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

if failed_attempts >= MAX_ATTEMPTS:
    if locked_until and datetime.now() < locked_until:
        return error("Account locked")
```

**Session config:**
```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
```

---

## Step 4: Database Queries

**Always use parameterized queries:**

```python
# CORRECT
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# CORRECT with ORM
User.query.filter_by(id=user_id).first()

# NEVER DO THIS
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

---

## Step 5: API Endpoints

**Add security headers to all responses:**

```python
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

**Handle errors safely:**
```python
try:
    result = process_data(data)
    return jsonify({"status": "ok", "data": result})
except Exception as e:
    logger.error(f"Error: {e}")  # Log details
    return jsonify({"error": "An error occurred"}), 500  # Generic message
```

---

## Step 6: Audit Logging

**Log security events:**

```python
import json
import logging
from datetime import datetime

def log_event(event_type: str, user_id: str, ip: str, details: dict = None):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": event_type,
        "user_id": user_id,
        "ip_address": ip,
        "details": details or {}
    }
    logging.getLogger("audit").info(json.dumps(entry))

# Usage
log_event("login_success", user.id, request.remote_addr)
log_event("login_failure", username, request.remote_addr, {"reason": "invalid_password"})
```

---

## Step 7: Secrets Management

**Never hardcode secrets:**

```python
# CORRECT
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
DATABASE_URL = os.environ.get('DATABASE_URL')

# NEVER DO THIS
SECRET_KEY = "hardcoded-secret-key-12345"
```

---

## Quick Checklist

Before completing task:
- [ ] Input validation on all user inputs
- [ ] Input sanitization applied
- [ ] Parameterized database queries
- [ ] No hardcoded secrets
- [ ] Security headers on responses
- [ ] Generic error messages to users
- [ ] Security events logged
- [ ] Passwords hashed with bcrypt

---

## SonarQube Integration

If PR triggers SonarQube scan:
1. **Critical/High issues** → Must fix before merge
2. **Security hotspots** → Review and resolve
3. **Coverage < 80%** → Add tests

---

**Reference:** https://github.com/COG-GTM/fedreral_security_comliance
