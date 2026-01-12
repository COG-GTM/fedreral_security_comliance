"""
STIG-Compliant Authentication and Session Management Module
Implements V-220629, V-220630 (Authentication & Access Control)
"""

import bcrypt
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class UserRole(Enum):
    """User roles for RBAC (Role-Based Access Control)"""
    GUEST = "guest"
    USER = "user"
    ADMIN = "admin"


@dataclass
class User:
    """User data structure"""
    user_id: str
    username: str
    password_hash: str
    role: UserRole = UserRole.USER
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    account_locked_until: Optional[datetime] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None


@dataclass
class Session:
    """Session data structure"""
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    csrf_token: str


class PasswordPolicy:
    """STIG V-220629: Password policy enforcement"""
    
    MIN_LENGTH = 14
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    MAX_AGE_DAYS = 90
    
    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """
        Validate password against STIG requirements
        Returns (is_valid, error_message)
        """
        if len(password) < PasswordPolicy.MIN_LENGTH:
            return False, f"Password must be at least {PasswordPolicy.MIN_LENGTH} characters"
        
        if PasswordPolicy.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if PasswordPolicy.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if PasswordPolicy.REQUIRE_DIGIT and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        if PasswordPolicy.REQUIRE_SPECIAL and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"
        
        return True, ""


class AuthenticationManager:
    """STIG V-220629, V-220630: Authentication and access control"""
    
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    SESSION_TIMEOUT_MINUTES = 15
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt with salt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash using constant-time comparison"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def create_user(self, username: str, password: str, role: UserRole = UserRole.USER) -> tuple[bool, str]:
        """
        Create new user with password policy validation
        Returns (success, message)
        """
        # Validate password
        is_valid, error_msg = PasswordPolicy.validate_password(password)
        if not is_valid:
            logger.warning(f"Password policy violation for user {username}: {error_msg}")
            return False, error_msg
        
        # Check if user exists
        if username in self.users:
            return False, "Username already exists"
        
        # Create user
        user_id = secrets.token_urlsafe(16)
        password_hash = self.hash_password(password)
        
        user = User(
            user_id=user_id,
            username=username,
            password_hash=password_hash,
            role=role
        )
        
        self.users[username] = user
        logger.info(f"User created: {username} with role {role.value}")
        return True, user_id
    
    def authenticate(self, username: str, password: str, ip_address: str) -> tuple[bool, Optional[str], str]:
        """
        Authenticate user with account lockout protection
        Returns (success, session_id, message)
        """
        user = self.users.get(username)
        
        if not user:
            logger.warning(f"Authentication failed: User not found - {username} from {ip_address}")
            return False, None, "Invalid credentials"
        
        # Check account lockout
        if user.account_locked_until:
            if datetime.now() < user.account_locked_until:
                remaining = (user.account_locked_until - datetime.now()).seconds // 60
                logger.warning(f"Authentication blocked: Account locked - {username} from {ip_address}")
                return False, None, f"Account locked. Try again in {remaining} minutes"
            else:
                # Unlock account
                user.account_locked_until = None
                user.failed_login_attempts = 0
        
        # Verify password
        if not self.verify_password(password, user.password_hash):
            user.failed_login_attempts += 1
            logger.warning(f"Authentication failed: Invalid password - {username} from {ip_address} (attempt {user.failed_login_attempts})")
            
            # Lock account after max attempts
            if user.failed_login_attempts >= self.MAX_FAILED_ATTEMPTS:
                user.account_locked_until = datetime.now() + timedelta(minutes=self.LOCKOUT_DURATION_MINUTES)
                logger.warning(f"Account locked: {username} after {user.failed_login_attempts} failed attempts")
                return False, None, f"Account locked for {self.LOCKOUT_DURATION_MINUTES} minutes"
            
            return False, None, "Invalid credentials"
        
        # Successful authentication
        user.failed_login_attempts = 0
        user.last_login = datetime.now()
        
        # Create session
        session_id = self.create_session(user.user_id, ip_address, "")
        logger.info(f"Authentication successful: {username} from {ip_address}")
        
        return True, session_id, "Authentication successful"
    
    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        """Create new session with CSRF token"""
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        
        session = Session(
            session_id=session_id,
            user_id=user_id,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            ip_address=ip_address,
            user_agent=user_agent,
            csrf_token=csrf_token
        )
        
        self.sessions[session_id] = session
        logger.info(f"Session created: {session_id} for user {user_id}")
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str) -> tuple[bool, Optional[Session], str]:
        """
        Validate session with timeout check
        Returns (is_valid, session, message)
        """
        session = self.sessions.get(session_id)
        
        if not session:
            return False, None, "Invalid session"
        
        # Check session timeout
        timeout = timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
        if datetime.now() - session.last_activity > timeout:
            self.destroy_session(session_id)
            logger.info(f"Session expired: {session_id}")
            return False, None, "Session expired"
        
        # Verify IP address (prevent session hijacking)
        if session.ip_address != ip_address:
            logger.warning(f"Session IP mismatch: {session_id} - expected {session.ip_address}, got {ip_address}")
            self.destroy_session(session_id)
            return False, None, "Session validation failed"
        
        # Update last activity
        session.last_activity = datetime.now()
        return True, session, "Session valid"
    
    def destroy_session(self, session_id: str):
        """Destroy session (logout)"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            logger.info(f"Session destroyed: {session_id}")
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions to prevent memory bloat"""
        now = datetime.now()
        timeout = timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
        
        expired_sessions = [
            sid for sid, session in self.sessions.items()
            if now - session.last_activity > timeout
        ]
        
        for session_id in expired_sessions:
            self.destroy_session(session_id)
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    def check_permission(self, session_id: str, required_role: UserRole) -> bool:
        """Check if user has required role (RBAC)"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        user = next((u for u in self.users.values() if u.user_id == session.user_id), None)
        if not user:
            return False
        
        # Role hierarchy: ADMIN > USER > GUEST
        role_hierarchy = {UserRole.GUEST: 0, UserRole.USER: 1, UserRole.ADMIN: 2}
        return role_hierarchy[user.role] >= role_hierarchy[required_role]


def generate_secure_token() -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(32)
