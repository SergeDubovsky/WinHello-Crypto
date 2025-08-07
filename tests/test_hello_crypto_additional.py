import os
import sys
import asyncio
import ctypes
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

# Ensure project root is on path for direct imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Provide minimal ctypes.windll implementation for environments without it
if not hasattr(ctypes, 'windll'):
    ctypes.windll = MagicMock()
    ctypes.windll.kernel32 = MagicMock()
    ctypes.windll.user32 = MagicMock()

from hello_crypto import (
    FileEncryptor,
    WindowsHelloError,
    _bring_window_to_foreground,
    _find_and_focus_hello_dialog,
    KeyCredentialStatus,
)
from security_config import AES_KEY_SIZE


class TestEnsureKeyExists:
    @pytest.fixture
    def encryptor(self):
        return FileEncryptor()

    @pytest.mark.asyncio
    async def test_key_already_exists(self, encryptor):
        mock_open = MagicMock()
        mock_open.status = KeyCredentialStatus.SUCCESS
        with patch('hello_crypto.KeyCredentialManager.open_async', AsyncMock(return_value=mock_open)) as mock_open_async, \
             patch('hello_crypto.KeyCredentialManager.request_create_async', AsyncMock()) as mock_create:
            await encryptor.ensure_key_exists()
            mock_open_async.assert_awaited()
            mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_key_when_missing(self, encryptor):
        mock_open = MagicMock()
        mock_open.status = 1  # Failure code
        mock_create = MagicMock()
        mock_create.status = KeyCredentialStatus.SUCCESS
        with patch('hello_crypto.KeyCredentialManager.open_async', AsyncMock(return_value=mock_open)), \
             patch('hello_crypto.KeyCredentialManager.request_create_async', AsyncMock(return_value=mock_create)) as mock_request:
            await encryptor.ensure_key_exists()
            mock_request.assert_awaited()

    @pytest.mark.asyncio
    async def test_create_key_failure_raises(self, encryptor):
        mock_open = MagicMock()
        mock_open.status = 1
        mock_create = MagicMock()
        mock_create.status = 2  # Not SUCCESS
        with patch('hello_crypto.KeyCredentialManager.open_async', AsyncMock(return_value=mock_open)), \
             patch('hello_crypto.KeyCredentialManager.request_create_async', AsyncMock(return_value=mock_create)):
            with pytest.raises(WindowsHelloError):
                await encryptor.ensure_key_exists()


class TestExtractSignatureBytes:
    @pytest.fixture
    def encryptor(self):
        return FileEncryptor()

    @pytest.mark.asyncio
    async def test_extract_direct_bytes(self, encryptor):
        class Buffer:
            def __bytes__(self):
                return b'abc'
        result = await encryptor._extract_signature_bytes(Buffer())
        assert result == b'abc'

    @pytest.mark.asyncio
    async def test_extract_using_datareader(self, encryptor):
        class Buffer:
            length = 3
            def __bytes__(self):
                raise TypeError()
        mock_reader = MagicMock()
        mock_reader.read_bytes.return_value = b'def'
        with patch('hello_crypto.DataReader.from_buffer', return_value=mock_reader):
            result = await encryptor._extract_signature_bytes(Buffer())
            assert result == b'def'
            mock_reader.read_bytes.assert_called_once_with(3)

    @pytest.mark.asyncio
    async def test_extract_failure(self, encryptor):
        class Buffer:
            length = 0
            def __bytes__(self):
                raise TypeError()
        with patch('hello_crypto.DataReader.from_buffer', side_effect=Exception('boom')):
            with pytest.raises(WindowsHelloError):
                await encryptor._extract_signature_bytes(Buffer())


class TestDeriveKey:
    @pytest.mark.asyncio
    async def test_derive_key_success(self, monkeypatch):
        encryptor = FileEncryptor()

        monkeypatch.setenv('USERNAME', 'tester')
        monkeypatch.setenv('COMPUTERNAME', 'unitbox')

        mock_credential = MagicMock()
        mock_sign_result = MagicMock()
        mock_sign_result.status = KeyCredentialStatus.SUCCESS
        mock_sign_result.result = b'signature-buffer'
        mock_credential.request_sign_async = AsyncMock(return_value=mock_sign_result)

        mock_open_result = MagicMock()
        mock_open_result.status = KeyCredentialStatus.SUCCESS
        mock_open_result.credential = mock_credential

        mock_rate_limiter = MagicMock()

        mock_writer = MagicMock()
        mock_writer.detach_buffer.return_value = b'challenge'
        
        with patch('hello_crypto.KeyCredentialManager.open_async', AsyncMock(return_value=mock_open_result)), \
             patch('hello_crypto.DataWriter', return_value=mock_writer), \
             patch('hello_crypto.rate_limiter', mock_rate_limiter), \
             patch('hello_crypto.audit_log'), \
             patch('hello_crypto._bring_window_to_foreground'), \
             patch('hello_crypto._find_and_focus_hello_dialog', return_value=False), \
             patch.object(FileEncryptor, '_extract_signature_bytes', AsyncMock(return_value=b'signature')):
            key = await encryptor.derive_key_from_signature()
            assert isinstance(key, bytes)
            assert len(key) == AES_KEY_SIZE
            mock_rate_limiter.record_attempt.assert_called()


class TestWindowHelpers:
    def test_bring_window_to_foreground_noop(self):
        # Should simply return without error on non-Windows systems
        assert _bring_window_to_foreground() is None

    def test_find_and_focus_dialog_noop(self):
        # Should return False when Windows API unavailable
        assert _find_and_focus_hello_dialog() is False
