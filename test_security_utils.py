"""
Unit tests for security utilities
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from security_utils import (
    RateLimiter, SecurityError, ValidationError, RateLimitError,
    validate_file_path, validate_aws_credentials, validate_aws_region,
    validate_profile_name, secure_memory_clear, constant_time_compare,
    sanitize_error_message, create_integrity_hash, verify_integrity_hash
)

class TestRateLimiter:
    """Test rate limiting functionality."""
    
    def test_rate_limiter_allows_initial_attempts(self):
        limiter = RateLimiter()
        # Should not raise an exception for first few attempts
        for i in range(4):
            limiter.check_rate_limit("test_user")
            limiter.record_attempt("test_user", success=False)
    
    def test_rate_limiter_blocks_excessive_attempts(self):
        limiter = RateLimiter()
        # Record maximum attempts
        for i in range(5):
            limiter.check_rate_limit("test_user")
            limiter.record_attempt("test_user", success=False)
        
        # Next attempt should be blocked
        with pytest.raises(RateLimitError):
            limiter.check_rate_limit("test_user")
    
    def test_rate_limiter_resets_on_success(self):
        limiter = RateLimiter()
        # Record some failed attempts
        for i in range(3):
            limiter.check_rate_limit("test_user")
            limiter.record_attempt("test_user", success=False)
        
        # Record successful attempt
        limiter.record_attempt("test_user", success=True)
        
        # Should be able to attempt again
        limiter.check_rate_limit("test_user")

class TestFileValidation:
    """Test file path validation."""
    
    def test_validate_file_path_valid(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            path = validate_file_path(f.name, "read")
            assert isinstance(path, Path)
            os.unlink(f.name)
    
    def test_validate_file_path_blocked_extension(self):
        with pytest.raises(ValidationError, match="not allowed for security"):
            validate_file_path("malicious.exe", "read")
    
    def test_validate_file_path_traversal_attempt(self):
        with pytest.raises(ValidationError, match="Path traversal"):
            validate_file_path("../../../etc/passwd", "read")
    
    def test_validate_file_path_large_file(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            # Write a large file
            f.write(b'x' * (101 * 1024 * 1024))  # 101MB
            f.flush()
            
            with pytest.raises(ValidationError, match="File too large"):
                validate_file_path(f.name, "read")
            
            os.unlink(f.name)

class TestAWSValidation:
    """Test AWS credential validation."""
    
    def test_validate_aws_credentials_valid(self):
        # Should not raise exception
        validate_aws_credentials(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
    
    def test_validate_aws_credentials_invalid_access_key(self):
        with pytest.raises(ValidationError, match="Invalid AWS Access Key"):
            validate_aws_credentials(
                "INVALID_ACCESS_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )
    
    def test_validate_aws_credentials_invalid_secret_key(self):
        with pytest.raises(ValidationError, match="Invalid AWS Secret Key"):
            validate_aws_credentials(
                "AKIAIOSFODNN7EXAMPLE",
                "invalid_secret"
            )
    
    def test_validate_aws_region_valid(self):
        validate_aws_region("us-east-1")  # Should not raise
    
    def test_validate_aws_region_invalid(self):
        with pytest.raises(ValidationError, match="Invalid AWS region"):
            validate_aws_region("invalid-region-name")
    
    def test_validate_profile_name_valid(self):
        validate_profile_name("my-profile-123")  # Should not raise
    
    def test_validate_profile_name_invalid(self):
        with pytest.raises(ValidationError, match="Invalid profile name"):
            validate_profile_name("profile with spaces")

class TestSecurityFunctions:
    """Test security utility functions."""
    
    def test_secure_memory_clear(self):
        data = bytearray(b"sensitive_data")
        secure_memory_clear(data)
        # Data should be zeroed
        assert all(b == 0 for b in data)
    
    def test_constant_time_compare(self):
        data1 = b"test_data"
        data2 = b"test_data"
        data3 = b"different"
        
        assert constant_time_compare(data1, data2) is True
        assert constant_time_compare(data1, data3) is False
    
    def test_sanitize_error_message(self):
        # Test that sensitive keywords are sanitized
        error = Exception("Key derivation failed with secret: abc123")
        sanitized = sanitize_error_message(error, "encryption")
        assert "secret" not in sanitized.lower()
        assert "key" not in sanitized.lower()
        assert "encryption" in sanitized
    
    def test_create_and_verify_integrity_hash(self):
        data = b"test_data_for_integrity"
        key = b"integrity_key_32_bytes_long_123"
        
        # Create hash
        hash_value = create_integrity_hash(data, key)
        assert len(hash_value) == 32  # SHA-256 output
        
        # Verify hash
        assert verify_integrity_hash(data, key, hash_value) is True
        
        # Verify with wrong data
        wrong_data = b"wrong_data"
        assert verify_integrity_hash(wrong_data, key, hash_value) is False

class TestExceptionHandling:
    """Test custom exception classes."""
    
    def test_security_error(self):
        with pytest.raises(SecurityError):
            raise SecurityError("Test security error")
    
    def test_validation_error(self):
        with pytest.raises(ValidationError):
            raise ValidationError("Test validation error")
    
    def test_rate_limit_error(self):
        with pytest.raises(RateLimitError):
            raise RateLimitError("Test rate limit error")

if __name__ == "__main__":
    pytest.main([__file__])