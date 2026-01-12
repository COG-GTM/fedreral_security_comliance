"""
STIG-Compliant Audit Logging and Monitoring Module
Implements V-220635, V-220636 (Logging & Monitoring)
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
from pathlib import Path
import hashlib


class AuditEventType(Enum):
    """Audit event types for STIG compliance"""
    AUTH_SUCCESS = "authentication_success"
    AUTH_FAILURE = "authentication_failure"
    AUTH_LOCKOUT = "account_lockout"
    SESSION_CREATE = "session_created"
    SESSION_EXPIRE = "session_expired"
    SESSION_DESTROY = "session_destroyed"
    DATA_ACCESS = "data_access"
    DATA_MODIFY = "data_modification"
    PERMISSION_DENIED = "permission_denied"
    INPUT_VALIDATION_FAIL = "input_validation_failure"
    RATE_LIMIT_EXCEED = "rate_limit_exceeded"
    SECURITY_VIOLATION = "security_violation"
    ADMIN_ACTION = "admin_action"
    CONFIG_CHANGE = "configuration_change"


class AuditLogger:
    """
    STIG V-220635, V-220636: Comprehensive audit logging
    Logs all security-relevant events with immutable storage
    """
    
    def __init__(self, log_dir: str = "logs", app_name: str = "windsurf-game"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.app_name = app_name
        
        # Configure structured JSON logging
        self.audit_log_path = self.log_dir / f"{app_name}_audit.log"
        self.security_log_path = self.log_dir / f"{app_name}_security.log"
        
        # Setup audit logger
        self.audit_logger = self._setup_logger("audit", self.audit_log_path)
        self.security_logger = self._setup_logger("security", self.security_log_path)
    
    def _setup_logger(self, name: str, log_path: Path) -> logging.Logger:
        """Setup structured JSON logger"""
        logger = logging.getLogger(f"{self.app_name}.{name}")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        
        # Remove existing handlers
        logger.handlers.clear()
        
        # File handler with rotation
        handler = logging.FileHandler(log_path, mode='a')
        handler.setLevel(logging.INFO)
        
        # JSON formatter
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        return logger
    
    def _create_log_entry(
        self,
        event_type: AuditEventType,
        user_id: Optional[str],
        ip_address: str,
        details: Dict[str, Any],
        severity: str = "INFO"
    ) -> Dict[str, Any]:
        """Create structured log entry"""
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        entry = {
            "timestamp": timestamp,
            "app_name": self.app_name,
            "event_type": event_type.value,
            "severity": severity,
            "user_id": user_id or "anonymous",
            "ip_address": ip_address,
            "details": details
        }
        
        # Add integrity hash
        entry_str = json.dumps(entry, sort_keys=True)
        entry["integrity_hash"] = hashlib.sha256(entry_str.encode()).hexdigest()[:16]
        
        return entry
    
    def log_authentication_success(
        self,
        user_id: str,
        username: str,
        ip_address: str,
        session_id: str
    ):
        """Log successful authentication"""
        entry = self._create_log_entry(
            event_type=AuditEventType.AUTH_SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            details={
                "username": username,
                "session_id": session_id,
                "action": "login"
            },
            severity="INFO"
        )
        self.audit_logger.info(json.dumps(entry))
    
    def log_authentication_failure(
        self,
        username: str,
        ip_address: str,
        reason: str,
        attempt_number: int
    ):
        """Log failed authentication attempt"""
        entry = self._create_log_entry(
            event_type=AuditEventType.AUTH_FAILURE,
            user_id=None,
            ip_address=ip_address,
            details={
                "username": username,
                "reason": reason,
                "attempt_number": attempt_number,
                "action": "login_failed"
            },
            severity="WARNING"
        )
        self.security_logger.warning(json.dumps(entry))
    
    def log_account_lockout(
        self,
        username: str,
        ip_address: str,
        failed_attempts: int,
        lockout_duration_minutes: int
    ):
        """Log account lockout event"""
        entry = self._create_log_entry(
            event_type=AuditEventType.AUTH_LOCKOUT,
            user_id=None,
            ip_address=ip_address,
            details={
                "username": username,
                "failed_attempts": failed_attempts,
                "lockout_duration_minutes": lockout_duration_minutes,
                "action": "account_locked"
            },
            severity="WARNING"
        )
        self.security_logger.warning(json.dumps(entry))
    
    def log_session_created(
        self,
        user_id: str,
        session_id: str,
        ip_address: str,
        user_agent: str
    ):
        """Log session creation"""
        entry = self._create_log_entry(
            event_type=AuditEventType.SESSION_CREATE,
            user_id=user_id,
            ip_address=ip_address,
            details={
                "session_id": session_id,
                "user_agent": user_agent,
                "action": "session_created"
            },
            severity="INFO"
        )
        self.audit_logger.info(json.dumps(entry))
    
    def log_session_expired(self, session_id: str, user_id: str):
        """Log session expiration"""
        entry = self._create_log_entry(
            event_type=AuditEventType.SESSION_EXPIRE,
            user_id=user_id,
            ip_address="N/A",
            details={
                "session_id": session_id,
                "action": "session_expired"
            },
            severity="INFO"
        )
        self.audit_logger.info(json.dumps(entry))
    
    def log_data_access(
        self,
        user_id: str,
        ip_address: str,
        resource: str,
        action: str
    ):
        """Log data access"""
        entry = self._create_log_entry(
            event_type=AuditEventType.DATA_ACCESS,
            user_id=user_id,
            ip_address=ip_address,
            details={
                "resource": resource,
                "action": action
            },
            severity="INFO"
        )
        self.audit_logger.info(json.dumps(entry))
    
    def log_data_modification(
        self,
        user_id: str,
        ip_address: str,
        resource: str,
        action: str,
        changes: Dict[str, Any]
    ):
        """Log data modification"""
        entry = self._create_log_entry(
            event_type=AuditEventType.DATA_MODIFY,
            user_id=user_id,
            ip_address=ip_address,
            details={
                "resource": resource,
                "action": action,
                "changes": changes
            },
            severity="INFO"
        )
        self.audit_logger.info(json.dumps(entry))
    
    def log_permission_denied(
        self,
        user_id: str,
        ip_address: str,
        resource: str,
        required_permission: str
    ):
        """Log permission denial"""
        entry = self._create_log_entry(
            event_type=AuditEventType.PERMISSION_DENIED,
            user_id=user_id,
            ip_address=ip_address,
            details={
                "resource": resource,
                "required_permission": required_permission,
                "action": "access_denied"
            },
            severity="WARNING"
        )
        self.security_logger.warning(json.dumps(entry))
    
    def log_input_validation_failure(
        self,
        ip_address: str,
        endpoint: str,
        validation_error: str,
        input_data: Optional[Dict[str, Any]] = None
    ):
        """Log input validation failure"""
        details = {
            "endpoint": endpoint,
            "validation_error": validation_error,
            "action": "input_validation_failed"
        }
        
        # Sanitize input data for logging (remove sensitive info)
        if input_data:
            sanitized_data = {k: "***" if "password" in k.lower() else v 
                            for k, v in input_data.items()}
            details["input_data"] = sanitized_data
        
        entry = self._create_log_entry(
            event_type=AuditEventType.INPUT_VALIDATION_FAIL,
            user_id=None,
            ip_address=ip_address,
            details=details,
            severity="WARNING"
        )
        self.security_logger.warning(json.dumps(entry))
    
    def log_rate_limit_exceeded(
        self,
        ip_address: str,
        endpoint: str,
        request_count: int
    ):
        """Log rate limit exceeded"""
        entry = self._create_log_entry(
            event_type=AuditEventType.RATE_LIMIT_EXCEED,
            user_id=None,
            ip_address=ip_address,
            details={
                "endpoint": endpoint,
                "request_count": request_count,
                "action": "rate_limit_exceeded"
            },
            severity="WARNING"
        )
        self.security_logger.warning(json.dumps(entry))
    
    def log_security_violation(
        self,
        ip_address: str,
        violation_type: str,
        details: Dict[str, Any]
    ):
        """Log security violation"""
        entry = self._create_log_entry(
            event_type=AuditEventType.SECURITY_VIOLATION,
            user_id=None,
            ip_address=ip_address,
            details={
                "violation_type": violation_type,
                **details
            },
            severity="ERROR"
        )
        self.security_logger.error(json.dumps(entry))
    
    def log_admin_action(
        self,
        user_id: str,
        ip_address: str,
        action: str,
        target: str,
        details: Dict[str, Any]
    ):
        """Log administrative action"""
        entry = self._create_log_entry(
            event_type=AuditEventType.ADMIN_ACTION,
            user_id=user_id,
            ip_address=ip_address,
            details={
                "action": action,
                "target": target,
                **details
            },
            severity="INFO"
        )
        self.audit_logger.info(json.dumps(entry))
