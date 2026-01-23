"""
EY Demo: AI-Assisted Secure Code Generation
============================================
This Flask API demonstrates automatic application of STIG/NIST security controls
using the Federal Security Compliance Framework.

STIG Controls Implemented:
- V-220629: Authentication with bcrypt hashing and account lockout
- V-220630: Session security with 15-minute timeout
- V-220631: Input validation using whitelist approach
- V-220632: Input sanitization to prevent injection
- V-220635: Structured JSON audit logging
- V-220636: Rate limiting to prevent abuse
- V-220641: Security headers (HSTS, CSP, X-Frame-Options)

NIST 800-53 Control Families:
- IA-2, IA-5: Identification and Authentication
- AC-7, AC-12: Access Control
- SI-10: Information Input Validation
- AU-2, AU-3: Audit and Accountability
- SI-11: Error Handling
"""

import os
import sys
from datetime import timedelta
from functools import wraps

from flask import Flask, request, jsonify, g

# Add templates directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'templates', 'python'))

from security_utils import (  # noqa: E402
    InputValidator, InputSanitizer, RateLimiter, ContentSecurityPolicy
)
from auth_manager import AuthenticationManager, UserRole  # noqa: E402
from audit_logger import AuditLogger  # noqa: E402


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

auth_manager = AuthenticationManager()
audit_logger = AuditLogger(log_dir="logs", app_name="ey-secure-api")
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
login_rate_limiter = RateLimiter(max_requests=5, window_seconds=60)


@app.after_request
def add_security_headers(response):
    """
    STIG V-220641: Add required security headers to all responses
    Maps to NIST SI-11 (Error Handling)
    """
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = ContentSecurityPolicy.get_policy()
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


def require_auth(f):
    """
    Decorator to require valid session for protected endpoints
    STIG V-220630: Session validation with timeout check
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        session_id = request.headers.get('X-Session-ID')

        if not session_id:
            audit_logger.log_permission_denied(
                user_id="anonymous",
                ip_address=client_ip,
                resource=request.path,
                required_permission="valid_session"
            )
            return jsonify({"error": "Authentication required"}), 401

        is_valid, session, message = auth_manager.validate_session(session_id, client_ip)

        if not is_valid:
            audit_logger.log_permission_denied(
                user_id="anonymous",
                ip_address=client_ip,
                resource=request.path,
                required_permission="valid_session"
            )
            return jsonify({"error": "Session invalid or expired"}), 401

        g.session = session
        g.user_id = session.user_id
        return f(*args, **kwargs)

    return decorated_function


def require_role(required_role: UserRole):
    """
    Decorator for Role-Based Access Control (RBAC)
    STIG V-220629: Authorization enforcement
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            session_id = request.headers.get('X-Session-ID')

            if not auth_manager.check_permission(session_id, required_role):
                audit_logger.log_permission_denied(
                    user_id=getattr(g, 'user_id', 'anonymous'),
                    ip_address=client_ip,
                    resource=request.path,
                    required_permission=required_role.value
                )
                return jsonify({"error": "Insufficient permissions"}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route("/api/register", methods=["POST"])
def register():
    """
    User Registration Endpoint

    Security Controls Applied:
    - STIG V-220631: Input validation (username, email format)
    - STIG V-220632: Input sanitization
    - STIG V-220629: Password policy enforcement (14+ chars, complexity)
    - STIG V-220635: Audit logging of registration events
    - STIG V-220636: Rate limiting
    """
    client_ip = request.remote_addr

    if not rate_limiter.is_allowed(client_ip):
        audit_logger.log_rate_limit_exceeded(
            ip_address=client_ip,
            endpoint="/api/register",
            request_count=100
        )
        return jsonify({"error": "Too many requests. Please try again later."}), 429

    data = request.get_json()
    if not data:
        audit_logger.log_input_validation_failure(
            ip_address=client_ip,
            endpoint="/api/register",
            validation_error="Missing request body"
        )
        return jsonify({"error": "Invalid request"}), 400

    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')

    if not InputValidator.validate_username(username):
        audit_logger.log_input_validation_failure(
            ip_address=client_ip,
            endpoint="/api/register",
            validation_error="Invalid username format",
            input_data={"username": username}
        )
        return jsonify({"error": "Invalid username format. Use 3-32 alphanumeric characters."}), 400

    if not InputValidator.validate_email(email):
        audit_logger.log_input_validation_failure(
            ip_address=client_ip,
            endpoint="/api/register",
            validation_error="Invalid email format",
            input_data={"email": email}
        )
        return jsonify({"error": "Invalid email format"}), 400

    sanitized_username = InputSanitizer.sanitize_string(username, max_length=32)
    if not sanitized_username:
        return jsonify({"error": "Invalid username"}), 400

    success, result = auth_manager.create_user(sanitized_username, password, UserRole.USER)

    if not success:
        audit_logger.log_input_validation_failure(
            ip_address=client_ip,
            endpoint="/api/register",
            validation_error=result,
            input_data={"username": sanitized_username}
        )
        return jsonify({"error": result}), 400

    audit_logger.log_admin_action(
        user_id=result,
        ip_address=client_ip,
        action="user_registration",
        target=sanitized_username,
        details={"email": email, "role": UserRole.USER.value}
    )

    return jsonify({
        "status": "success",
        "message": "User registered successfully",
        "user_id": result
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    """
    User Login Endpoint

    Security Controls Applied:
    - STIG V-220631: Input validation (username format)
    - STIG V-220629: Authentication with bcrypt, account lockout after 5 attempts
    - STIG V-220630: Session creation with 15-minute timeout
    - STIG V-220635: Audit logging (success/failure events)
    - STIG V-220636: Stricter rate limiting for login (5 requests/minute)
    """
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')

    if not login_rate_limiter.is_allowed(client_ip):
        audit_logger.log_rate_limit_exceeded(
            ip_address=client_ip,
            endpoint="/api/login",
            request_count=5
        )
        return jsonify({"error": "Too many login attempts. Please try again later."}), 429

    data = request.get_json()
    if not data:
        audit_logger.log_input_validation_failure(
            ip_address=client_ip,
            endpoint="/api/login",
            validation_error="Missing request body"
        )
        return jsonify({"error": "Invalid request"}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    if not InputValidator.validate_username(username):
        audit_logger.log_input_validation_failure(
            ip_address=client_ip,
            endpoint="/api/login",
            validation_error="Invalid username format",
            input_data={"username": username}
        )
        return jsonify({"error": "Invalid credentials"}), 401

    success, session_id, message = auth_manager.authenticate(username, password, client_ip)

    if not success:
        user = auth_manager.users.get(username)
        attempt_number = user.failed_login_attempts if user else 1

        audit_logger.log_authentication_failure(
            username=username,
            ip_address=client_ip,
            reason=message,
            attempt_number=attempt_number
        )

        if user and user.account_locked_until:
            audit_logger.log_account_lockout(
                username=username,
                ip_address=client_ip,
                failed_attempts=auth_manager.MAX_FAILED_ATTEMPTS,
                lockout_duration_minutes=auth_manager.LOCKOUT_DURATION_MINUTES
            )

        return jsonify({"error": "Invalid credentials"}), 401

    user = auth_manager.users.get(username)
    audit_logger.log_authentication_success(
        user_id=user.user_id,
        username=username,
        ip_address=client_ip,
        session_id=session_id
    )

    audit_logger.log_session_created(
        user_id=user.user_id,
        session_id=session_id,
        ip_address=client_ip,
        user_agent=user_agent
    )

    response = jsonify({
        "status": "success",
        "message": "Login successful",
        "session_id": session_id,
        "csrf_token": auth_manager.sessions[session_id].csrf_token
    })

    response.set_cookie(
        'session_id',
        session_id,
        httponly=True,
        secure=True,
        samesite='Strict',
        max_age=900
    )

    return response, 200


@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    """
    User Logout Endpoint

    Security Controls Applied:
    - STIG V-220630: Session destruction
    - STIG V-220635: Audit logging of logout events
    """
    session_id = request.headers.get('X-Session-ID')

    auth_manager.destroy_session(session_id)

    audit_logger.log_session_expired(
        session_id=session_id,
        user_id=g.user_id
    )

    response = jsonify({"status": "success", "message": "Logged out successfully"})
    response.delete_cookie('session_id')

    return response, 200


@app.route("/api/data", methods=["GET"])
@require_auth
def get_data():
    """
    Protected Data Access Endpoint

    Security Controls Applied:
    - STIG V-220630: Session validation required
    - STIG V-220635: Data access audit logging
    - STIG V-220636: Rate limiting
    """
    client_ip = request.remote_addr

    if not rate_limiter.is_allowed(client_ip):
        audit_logger.log_rate_limit_exceeded(
            ip_address=client_ip,
            endpoint="/api/data",
            request_count=100
        )
        return jsonify({"error": "Too many requests"}), 429

    audit_logger.log_data_access(
        user_id=g.user_id,
        ip_address=client_ip,
        resource="/api/data",
        action="read"
    )

    return jsonify({
        "status": "success",
        "data": {
            "message": "This is protected data",
            "user_id": g.user_id
        }
    }), 200


@app.route("/api/data", methods=["POST"])
@require_auth
def update_data():
    """
    Protected Data Modification Endpoint

    Security Controls Applied:
    - STIG V-220630: Session validation required
    - STIG V-220631: Input validation
    - STIG V-220632: Input sanitization
    - STIG V-220635: Data modification audit logging
    - STIG V-220636: Rate limiting
    """
    client_ip = request.remote_addr

    if not rate_limiter.is_allowed(client_ip):
        audit_logger.log_rate_limit_exceeded(
            ip_address=client_ip,
            endpoint="/api/data",
            request_count=100
        )
        return jsonify({"error": "Too many requests"}), 429

    data = request.get_json()
    if not data:
        audit_logger.log_input_validation_failure(
            ip_address=client_ip,
            endpoint="/api/data",
            validation_error="Missing request body"
        )
        return jsonify({"error": "Invalid request"}), 400

    sanitized_data = InputSanitizer.sanitize_player_data(data)
    if sanitized_data is None:
        audit_logger.log_input_validation_failure(
            ip_address=client_ip,
            endpoint="/api/data",
            validation_error="Invalid data format",
            input_data=data
        )
        return jsonify({"error": "Invalid data format"}), 400

    audit_logger.log_data_modification(
        user_id=g.user_id,
        ip_address=client_ip,
        resource="/api/data",
        action="update",
        changes=sanitized_data
    )

    return jsonify({
        "status": "success",
        "message": "Data updated successfully",
        "data": sanitized_data
    }), 200


@app.route("/api/admin/users", methods=["GET"])
@require_auth
@require_role(UserRole.ADMIN)
def admin_list_users():
    """
    Admin-Only Endpoint: List Users

    Security Controls Applied:
    - STIG V-220629: RBAC - Admin role required
    - STIG V-220630: Session validation
    - STIG V-220635: Admin action audit logging
    """
    client_ip = request.remote_addr

    audit_logger.log_admin_action(
        user_id=g.user_id,
        ip_address=client_ip,
        action="list_users",
        target="all_users",
        details={"count": len(auth_manager.users)}
    )

    users = [
        {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "created_at": user.created_at.isoformat()
        }
        for user in auth_manager.users.values()
    ]

    return jsonify({
        "status": "success",
        "users": users
    }), 200


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint - no authentication required"""
    return jsonify({"status": "healthy"}), 200


@app.errorhandler(Exception)
def handle_error(error):
    """
    STIG V-220641: Generic error handling
    - Return generic message to users
    - Log detailed error internally
    """
    client_ip = request.remote_addr

    audit_logger.log_security_violation(
        ip_address=client_ip,
        violation_type="unhandled_exception",
        details={"error_type": type(error).__name__}
    )

    return jsonify({"error": "An error occurred"}), 500


if __name__ == "__main__":
    success, admin_id = auth_manager.create_user(
        "admin",
        "SecureAdmin@Password123!",
        UserRole.ADMIN
    )
    if success:
        print(f"Demo admin user created: admin (ID: {admin_id})")

    app.run(host="0.0.0.0", port=5000, debug=False)
