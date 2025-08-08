import os
import sys
import time
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_utils import (
    RateLimiter,
    RateLimitError,
    ValidationError,
    validate_file_path,
    secure_memory_clear,
    sanitize_error_message,
    generate_secure_random,
)
from security_config import MAX_AUTH_ATTEMPTS, LOCKOUT_DURATION


def test_record_attempt_initializes():
    limiter = RateLimiter()
    limiter.record_attempt("user1")
    assert "user1" in limiter._attempts


def test_lockout_expiration_and_clear():
    limiter = RateLimiter()
    ident = "user2"
    limiter._lockouts[ident] = time.time() - LOCKOUT_DURATION - 1
    limiter.check_rate_limit(ident)
    assert ident not in limiter._lockouts
    limiter._lockouts[ident] = time.time()
    limiter.record_attempt(ident, success=True)
    assert ident not in limiter._lockouts


def test_validate_file_path_invalid_chars():
    with pytest.raises(ValidationError):
        validate_file_path(f"invalid{chr(0)}path", "read")


@pytest.mark.skipif(os.name == "nt", reason="symlink behaviour differs on Windows")
def test_validate_file_path_symlink_traversal():
    base = Path.cwd()
    with tempfile.TemporaryDirectory() as outside_dir:
        outside_file = Path(outside_dir) / "data.txt"
        outside_file.write_text("test")
        link_path = base / "outside_link.txt"
        os.symlink(outside_file, link_path)
        try:
            rel = os.path.relpath(link_path, start=base)
            with pytest.raises(ValidationError):
                validate_file_path(rel, "read")
        finally:
            link_path.unlink(missing_ok=True)


def test_secure_memory_clear_empty_and_fallback():
    data = bytearray()
    secure_memory_clear(data)
    assert data == bytearray()
    data2 = bytearray(b"secret")
    with patch("platform.system", return_value="Windows"), patch("ctypes.windll", new=object()):
        secure_memory_clear(data2)
    assert all(b == 0 for b in data2)


def test_generate_secure_random():
    r1 = generate_secure_random(16)
    r2 = generate_secure_random(16)
    assert len(r1) == 16 and len(r2) == 16
    assert r1 != r2


def test_sanitize_error_message_network_and_default():
    net_err = Exception("Network timeout")
    assert sanitize_error_message(net_err, "connect") == "Network error during connect"
    generic = Exception("Something went wrong")
    assert sanitize_error_message(generic, "task") == "Operation failed: task"
