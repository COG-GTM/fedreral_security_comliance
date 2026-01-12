"""
STIG-Compliant Security Utilities Module
Implements V-220631, V-220632 (Input Validation & Sanitization)
"""

import re
import secrets
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class InputValidator:
    """STIG V-220631: Whitelist-based input validation"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email using whitelist pattern"""
        if not email or len(email) > 255:
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username: 3-32 alphanumeric chars, underscore, hyphen"""
        if not username or len(username) < 3 or len(username) > 32:
            return False
        pattern = r'^[a-zA-Z0-9_-]+$'
        return re.match(pattern, username) is not None
    
    @staticmethod
    def validate_numeric_range(value: Any, min_val: float, max_val: float) -> bool:
        """Validate numeric value within range"""
        try:
            num_value = float(value)
            return min_val <= num_value <= max_val
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_coordinate(coord: Any, world_size: int = 2000) -> bool:
        """Validate game coordinate within world bounds"""
        return InputValidator.validate_numeric_range(coord, 0, world_size)
    
    @staticmethod
    def validate_score(score: Any) -> bool:
        """Validate game score (non-negative integer)"""
        try:
            score_val = int(score)
            return score_val >= 0 and score_val <= 1000000
        except (ValueError, TypeError):
            return False


class InputSanitizer:
    """STIG V-220632: Input sanitization to prevent injection attacks"""
    
    @staticmethod
    def sanitize_string(user_input: str, max_length: int = 255) -> Optional[str]:
        """
        Sanitize string input by removing dangerous characters
        Prevents XSS, SQL injection, command injection
        """
        if not user_input or len(user_input) > max_length:
            return None
        
        # Remove dangerous characters: <>"';&|`$()
        sanitized = re.sub(r'[<>"\';&|`$()]', '', user_input.strip())
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        return sanitized if sanitized else None
    
    @staticmethod
    def sanitize_numeric(value: Any) -> Optional[float]:
        """Sanitize numeric input"""
        try:
            return float(value)
        except (ValueError, TypeError):
            logger.warning(f"Failed to sanitize numeric value: {value}")
            return None
    
    @staticmethod
    def sanitize_player_data(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Sanitize player update data
        Returns None if validation fails
        """
        if not isinstance(data, dict):
            return None
        
        sanitized = {}
        
        # Validate and sanitize x coordinate
        if 'x' in data:
            x = InputSanitizer.sanitize_numeric(data['x'])
            if x is None or not InputValidator.validate_coordinate(x):
                logger.warning(f"Invalid x coordinate: {data.get('x')}")
                return None
            sanitized['x'] = x
        
        # Validate and sanitize y coordinate
        if 'y' in data:
            y = InputSanitizer.sanitize_numeric(data['y'])
            if y is None or not InputValidator.validate_coordinate(y):
                logger.warning(f"Invalid y coordinate: {data.get('y')}")
                return None
            sanitized['y'] = y
        
        # Validate and sanitize score
        if 'score' in data:
            score = InputSanitizer.sanitize_numeric(data['score'])
            if score is None or not InputValidator.validate_score(score):
                logger.warning(f"Invalid score: {data.get('score')}")
                return None
            sanitized['score'] = int(score)
        
        # Sanitize player name if present
        if 'name' in data:
            name = InputSanitizer.sanitize_string(data['name'], max_length=32)
            if name and InputValidator.validate_username(name):
                sanitized['name'] = name
        
        return sanitized


class CSRFProtection:
    """STIG V-220632: CSRF token generation and validation"""
    
    @staticmethod
    def generate_token() -> str:
        """Generate cryptographically secure CSRF token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_token(token: str, expected_token: str) -> bool:
        """Constant-time token comparison to prevent timing attacks"""
        if not token or not expected_token:
            return False
        return secrets.compare_digest(token, expected_token)


class RateLimiter:
    """STIG V-220636: Rate limiting to prevent abuse"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = {}
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed based on rate limit"""
        now = datetime.now()
        
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Remove old requests outside the time window
        cutoff = now - timedelta(seconds=self.window_seconds)
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if req_time > cutoff
        ]
        
        # Check if under limit
        if len(self.requests[identifier]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for identifier: {identifier}")
            return False
        
        # Add current request
        self.requests[identifier].append(now)
        return True
    
    def cleanup_old_entries(self):
        """Cleanup old entries to prevent memory bloat"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds * 2)
        
        for identifier in list(self.requests.keys()):
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > cutoff
            ]
            if not self.requests[identifier]:
                del self.requests[identifier]


class ContentSecurityPolicy:
    """STIG V-220641: Content Security Policy header generation"""
    
    @staticmethod
    def get_policy() -> str:
        """Generate strict CSP policy"""
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
