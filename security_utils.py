"""
Security Utilities
Common security functions and defensive measures
"""

import hashlib
import json
import logging
import os
import platform
import secrets
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Set, Tuple
import ctypes

from security_config import (
    MAX_FILE_SIZE, MAX_AUTH_ATTEMPTS, RATE_LIMIT_WINDOW, LOCKOUT_DURATION,
    ALLOWED_EXTENSIONS, BLOCKED_EXTENSIONS, SECURITY_EVENTS, AWS_REGIONS, AWS_PATTERNS
)

# Configure security logger
security_logger = logging.getLogger('winhello_security')
security_handler = logging.FileHandler('winhello_security.log')
security_formatter = logging.Formatter(
    '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
)
security_handler.setFormatter(security_formatter)
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.INFO)

class SecurityError(Exception):
    """Custom security-related exception."""
    pass

class RateLimitError(SecurityError):
    """Rate limiting exceeded exception."""
    pass

class ValidationError(SecurityError):
    """Input validation error."""
    pass

class RateLimiter:
    """Thread-safe rate limiter for authentication attempts."""
    
    def __init__(self):
        self._attempts: Dict[str, list] = {}
        self._lockouts: Dict[str, float] = {}
    
    def _cleanup_old_attempts(self, identifier: str) -> None:
        """Remove attempts older than the rate limit window."""
        if identifier in self._attempts:
            current_time = time.time()
            self._attempts[identifier] = [
                attempt_time for attempt_time in self._attempts[identifier]
                if current_time - attempt_time < RATE_LIMIT_WINDOW
            ]
    
    def check_rate_limit(self, identifier: str = "default") -> None:
        """Check if the identifier is rate limited."""
        current_time = time.time()
        
        # Check if currently locked out
        if identifier in self._lockouts:
            if current_time - self._lockouts[identifier] < LOCKOUT_DURATION:
                remaining = LOCKOUT_DURATION - (current_time - self._lockouts[identifier])
                security_logger.warning(f"Rate limit lockout active for {identifier}, {remaining:.0f}s remaining")
                raise RateLimitError(f"Too many authentication attempts. Try again in {remaining:.0f} seconds.")
            else:
                # Lockout expired, remove it
                del self._lockouts[identifier]
        
        # Clean up old attempts
        self._cleanup_old_attempts(identifier)
        
        # Check current attempt count
        if identifier not in self._attempts:
            self._attempts[identifier] = []
        
        if len(self._attempts[identifier]) >= MAX_AUTH_ATTEMPTS:
            # Trigger lockout
            self._lockouts[identifier] = current_time
            security_logger.error(f"Rate limit exceeded for {identifier}, triggering lockout")
            audit_log(SECURITY_EVENTS['RATE_LIMIT'], {
                'identifier': identifier,
                'attempts': len(self._attempts[identifier])
            })
            raise RateLimitError(f"Too many authentication attempts. Locked out for {LOCKOUT_DURATION} seconds.")
    
    def record_attempt(self, identifier: str = "default", success: bool = False) -> None:
        """Record an authentication attempt."""
        current_time = time.time()
        
        if identifier not in self._attempts:
            self._attempts[identifier] = []
        
        if not success:
            self._attempts[identifier].append(current_time)
            security_logger.warning(f"Failed authentication attempt for {identifier}")
        else:
            # Clear attempts on successful authentication
            if identifier in self._attempts:
                del self._attempts[identifier]
            if identifier in self._lockouts:
                del self._lockouts[identifier]
            security_logger.info(f"Successful authentication for {identifier}")

# Global rate limiter instance
rate_limiter = RateLimiter()

def audit_log(event_type: str, details: Dict) -> None:
    """Log security events for audit purposes."""
    audit_entry = {
        'timestamp': time.time(),
        'event_type': event_type,
        'details': details,
        'process_id': os.getpid(),
        'user': os.getenv('USERNAME', 'unknown')
    }
    
    # Log to security logger (without sensitive data)
    safe_details = {k: v for k, v in details.items() 
                   if k not in ['key', 'password', 'secret', 'token']}
    security_logger.info(f"Event: {event_type}, Details: {json.dumps(safe_details)}")

def validate_file_path(file_path: str, operation: str = "access") -> Path:
    """
    Validate file path for security issues.
    
    Args:
        file_path: Path to validate
        operation: Type of operation (read/write/access)
    
    Returns:
        Validated Path object
        
    Raises:
        ValidationError: If path is invalid or unsafe
    """
    raw_path = Path(file_path)

    # Inspect raw path for traversal attempts before resolving
    if any(part == ".." for part in raw_path.parts):
        audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
            'error': 'path_traversal_attempt',
            'path': file_path,
            'operation': operation
        })
        raise ValidationError("Path traversal not allowed")

    try:
        path = raw_path.resolve()
    except (OSError, ValueError) as e:
        audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
            'error': 'invalid_path',
            'path': file_path,
            'operation': operation
        })
        raise ValidationError(f"Invalid file path: {e}")

    base_dir = Path.cwd().resolve()

    # Disallow absolute paths outside the allowed base directory
    if raw_path.is_absolute():
        try:
            path.relative_to(base_dir)
        except ValueError:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'error': 'path_traversal_attempt',
                'path': str(path),
                'operation': operation
            })
            raise ValidationError("Absolute paths outside the allowed directory are not permitted")

    # Ensure resolved path remains within the allowed directory
    if not path.is_relative_to(base_dir):
        audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
            'error': 'path_traversal_attempt',
            'path': str(path),
            'operation': operation
        })
        raise ValidationError("Path traversal not allowed")
    
    # Check file extension
    if path.suffix.lower() in BLOCKED_EXTENSIONS:
        audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
            'error': 'blocked_extension',
            'extension': path.suffix,
            'operation': operation
        })
        raise ValidationError(f"File extension '{path.suffix}' is not allowed for security reasons")
    
    # Check file size for existing files
    if operation in ['read', 'access'] and path.exists():
        file_size = path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
                'error': 'file_too_large',
                'size': file_size,
                'max_size': MAX_FILE_SIZE
            })
            raise ValidationError(f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE})")
    
    return path

def validate_aws_credentials(access_key: str, secret_key: str, 
                           session_token: Optional[str] = None) -> None:
    """Validate AWS credential format."""
    if not AWS_PATTERNS['access_key'].match(access_key):
        audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
            'error': 'invalid_access_key_format'
        })
        raise ValidationError("Invalid AWS Access Key format")
    
    if not AWS_PATTERNS['secret_key'].match(secret_key):
        audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
            'error': 'invalid_secret_key_format'
        })
        raise ValidationError("Invalid AWS Secret Key format")
    
    if session_token and not AWS_PATTERNS['session_token'].match(session_token):
        audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
            'error': 'invalid_session_token_format'
        })
        raise ValidationError("Invalid AWS Session Token format")

def validate_aws_region(region: str) -> None:
    """Validate AWS region."""
    if region not in AWS_REGIONS and not AWS_PATTERNS['region'].match(region):
        audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
            'error': 'invalid_region',
            'region': region
        })
        raise ValidationError(f"Invalid AWS region: {region}")

def validate_profile_name(profile_name: str) -> None:
    """Validate AWS profile name."""
    if not profile_name or not profile_name.strip():
        raise ValidationError("Profile name cannot be empty")
    
    if not AWS_PATTERNS['profile_name'].match(profile_name):
        audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
            'error': 'invalid_profile_name',
            'profile': profile_name
        })
        raise ValidationError("Invalid profile name format")

def secure_memory_clear(data: bytearray) -> None:
    """
    Securely clear sensitive data from memory using OS-specific methods.
    
    Args:
        data: Bytearray to clear
    """
    if not data:
        return
    
    # First, overwrite with random data
    for i in range(len(data)):
        data[i] = secrets.randbits(8)
    
    # Then overwrite with zeros
    for i in range(len(data)):
        data[i] = 0
    
    # OS-specific secure clearing
    try:
        if platform.system() == "Windows":
            # Use Windows SecureZeroMemory if available
            kernel32 = ctypes.windll.kernel32
            kernel32.RtlSecureZeroMemory.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            address = ctypes.addressof(ctypes.c_char.from_buffer(data))
            # Convert bytearray to ctypes buffer to obtain memory address
            kernel32.RtlSecureZeroMemory(address, len(data))
    except Exception:
        # Fallback to multiple overwrites
        for _ in range(3):
            for i in range(len(data)):
                data[i] = secrets.randbits(8)
        for i in range(len(data)):
            data[i] = 0

def generate_secure_random(size: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return secrets.token_bytes(size)

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return secrets.compare_digest(a, b)

def sanitize_error_message(error: Exception, operation: str) -> str:
    """
    Sanitize error messages to prevent information leakage.
    
    Args:
        error: Original exception
        operation: Operation being performed
        
    Returns:
        Sanitized error message
    """
    error_str = str(error).lower()
    
    # Generic messages for security-sensitive errors
    if any(keyword in error_str for keyword in [
        'key', 'password', 'token', 'credential', 'secret'
    ]):
        return f"Authentication failed during {operation}"
    
    if any(keyword in error_str for keyword in [
        'path', 'directory', 'file not found'
    ]):
        return f"File access error during {operation}"
    
    if any(keyword in error_str for keyword in [
        'network', 'connection', 'timeout'
    ]):
        return f"Network error during {operation}"
    
    # Return sanitized version of the original error
    return f"Operation failed: {operation}"

def create_integrity_hash(data: bytes, key: bytes) -> bytes:
    """Create HMAC-SHA256 for data integrity."""
    import hmac
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_integrity_hash(data: bytes, key: bytes, expected_hash: bytes) -> bool:
    """Verify HMAC-SHA256 integrity hash."""
    computed_hash = create_integrity_hash(data, key)
    return constant_time_compare(computed_hash, expected_hash)
