"""
Test configuration and fixtures for pytest
"""

import pytest
import sys
import os
from unittest.mock import MagicMock

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

@pytest.fixture(autouse=True)
def mock_windows_modules():
    """Mock Windows-specific modules for cross-platform testing."""
    
    # Mock ctypes.windll for cross-platform compatibility
    import ctypes
    from unittest.mock import MagicMock
    
    # Only set up mocks if we're not on Windows or if windll access might fail
    original_windll = getattr(ctypes, 'windll', None)
    
    try:
        # Test if we can safely access windll
        if hasattr(ctypes, 'windll'):
            test_access = ctypes.windll.kernel32
    except Exception:
        # If windll access fails, set up mocks
        if not hasattr(ctypes, 'windll'):
            ctypes.windll = MagicMock()
        if not hasattr(ctypes.windll, 'kernel32'):
            ctypes.windll.kernel32 = MagicMock()
        if not hasattr(ctypes.windll, 'user32'):
            ctypes.windll.user32 = MagicMock()
    
    # Mock winrt modules
    winrt_mock = MagicMock()
    winrt_mock.windows = MagicMock()
    winrt_mock.windows.security = MagicMock()
    winrt_mock.windows.security.credentials = MagicMock()
    winrt_mock.windows.storage = MagicMock()
    winrt_mock.windows.storage.streams = MagicMock()
    
    # Mock specific Windows Hello classes
    KeyCredentialManager = MagicMock()
    KeyCredentialStatus = MagicMock()
    KeyCredentialStatus.SUCCESS = 0
    KeyCredentialCreationOption = MagicMock()
    KeyCredentialCreationOption.FAIL_IF_EXISTS = 0
    
    DataWriter = MagicMock()
    DataReader = MagicMock()
    
    # Set up the mock hierarchy
    winrt_mock.windows.security.credentials.KeyCredentialManager = KeyCredentialManager
    winrt_mock.windows.security.credentials.KeyCredentialStatus = KeyCredentialStatus
    winrt_mock.windows.security.credentials.KeyCredentialCreationOption = KeyCredentialCreationOption
    winrt_mock.windows.storage.streams.DataWriter = DataWriter
    winrt_mock.windows.storage.streams.DataReader = DataReader
    
    # Only mock if winrt is not available (e.g., on non-Windows CI)
    try:
        import winrt
    except ImportError:
        sys.modules['winrt'] = winrt_mock
        sys.modules['winrt.windows'] = winrt_mock.windows
        sys.modules['winrt.windows.security'] = winrt_mock.windows.security
        sys.modules['winrt.windows.security.credentials'] = winrt_mock.windows.security.credentials
        sys.modules['winrt.windows.storage'] = winrt_mock.windows.storage
        sys.modules['winrt.windows.storage.streams'] = winrt_mock.windows.storage.streams

@pytest.fixture
def mock_rate_limiter():
    """Mock rate limiter for testing."""
    from unittest.mock import MagicMock
    
    mock_limiter = MagicMock()
    mock_limiter.check_rate_limit = MagicMock()
    mock_limiter.record_attempt = MagicMock()
    
    return mock_limiter

@pytest.fixture
def disable_logging():
    """Disable logging during tests to reduce noise."""
    import logging
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)
