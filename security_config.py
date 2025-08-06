"""
Security Configuration and Constants
Centralized security settings for WinHello-Crypto
"""

import re
from typing import Dict, Any
from pathlib import Path

# File size limits (in bytes)
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_CREDENTIAL_SIZE = 64 * 1024     # 64KB

# Rate limiting settings
MAX_AUTH_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes in seconds
LOCKOUT_DURATION = 900   # 15 minutes in seconds

# Cryptographic constants
AES_GCM_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM
AES_GCM_TAG_SIZE = 16    # 128-bit authentication tag
AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32  # 256 bits
# Argon2id KDF parameters (OWASP recommended)
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 64 * 1024  # 64MB
ARGON2_PARALLELISM = 1
HMAC_SIZE = 32  # SHA-256 output size

# Windows Hello constants
KEY_NAME_FILE = "FileEncryptKey"
KEY_NAME_AWS = "AWSCredentialKey"
CHALLENGE_MESSAGE = "FixedChallengeForKeyDerivation"
AWS_CHALLENGE_MESSAGE = "AWSCredentialChallenge"

# AWS validation patterns
AWS_PATTERNS = {
    # AWS access keys typically start with specific prefixes like AKIA or ASIA
    # but may evolve over time. Accept known prefixes and fall back to a generic
    # 20-character alphanumeric pattern to remain future-proof.
    'access_key': re.compile(r'^(?:AKIA|ASIA|ACCA|[A-Z0-9]{4})[0-9A-Z]{16}$'),
    'secret_key': re.compile(r'^[A-Za-z0-9/+=]{40}$'),
    'session_token': re.compile(r'^[A-Za-z0-9/+=]{100,}$'),
    'profile_name': re.compile(r'^[a-zA-Z0-9-_\.]{1,64}$'),
    'region': re.compile(r'^[a-z0-9-]{1,32}$')
}

# Valid AWS regions (subset of most common ones)
AWS_REGIONS = {
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
    'ap-south-1', 'ca-central-1', 'sa-east-1'
}

# Security event types for audit logging
SECURITY_EVENTS = {
    'AUTH_SUCCESS': 'authentication_success',
    'AUTH_FAILURE': 'authentication_failure',
    'FILE_ENCRYPT': 'file_encryption',
    'FILE_DECRYPT': 'file_decryption',
    'FILE_DELETE': 'file_deletion',
    'CRED_STORE': 'credential_storage',
    'CRED_RETRIEVE': 'credential_retrieval',
    'RATE_LIMIT': 'rate_limit_exceeded',
    'VALIDATION_ERROR': 'validation_error',
    'SECURITY_ERROR': 'security_error'
}

# Allowed file extensions for encryption (security measure)
ALLOWED_EXTENSIONS = {
    '.txt', '.doc', '.docx', '.pdf', '.jpg', '.jpeg', '.png', '.gif',
    '.zip', '.tar', '.gz', '.7z', '.json', '.xml', '.csv', '.xlsx',
    '.ppt', '.pptx', '.mp4', '.avi', '.mp3', '.wav', '.sql', '.db'
}

# Blocked dangerous extensions
BLOCKED_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.msi', '.dll',
    '.sys', '.drv', '.vbs', '.js', '.jar', '.ps1', '.sh'
}

def get_security_config() -> Dict[str, Any]:
    """Get comprehensive security configuration."""
    return {
        'file_limits': {
            'max_file_size': MAX_FILE_SIZE,
            'max_credential_size': MAX_CREDENTIAL_SIZE,
            'allowed_extensions': ALLOWED_EXTENSIONS,
            'blocked_extensions': BLOCKED_EXTENSIONS
        },
        'rate_limiting': {
            'max_attempts': MAX_AUTH_ATTEMPTS,
            'window_seconds': RATE_LIMIT_WINDOW,
            'lockout_seconds': LOCKOUT_DURATION
        },
        'crypto': {
            'aes_key_size': AES_KEY_SIZE,
            'aes_block_size': AES_BLOCK_SIZE,
            'aes_gcm_nonce_size': AES_GCM_NONCE_SIZE,
            'aes_gcm_tag_size': AES_GCM_TAG_SIZE,
            'argon2_time_cost': ARGON2_TIME_COST,
            'argon2_memory_cost': ARGON2_MEMORY_COST,
            'argon2_parallelism': ARGON2_PARALLELISM,
            'hmac_size': HMAC_SIZE
        },
        'aws_validation': {
            'patterns': AWS_PATTERNS,
            'regions': AWS_REGIONS
        },
        'audit': {
            'events': SECURITY_EVENTS
        }
    }
