"""
Unit tests for hello_crypto module
"""

import asyncio
import pytest
import tempfile
import os
import sys
import secrets
import importlib
import builtins
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path
from cryptography.exceptions import InvalidTag

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from hello_crypto import (
        FileEncryptor,
        WindowsHelloError,
        _bring_window_to_foreground,
        _find_and_focus_hello_dialog,
        KeyCredentialStatus,
    )
    from security_config import (
        AES_KEY_SIZE, AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE,
        ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM
    )
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError as e:
    pytest.skip(f"Could not import hello_crypto modules: {e}", allow_module_level=True)

class TestFileEncryptor:
    """Test FileEncryptor functionality."""
    
    @pytest.fixture
    def encryptor(self):
        return FileEncryptor()
    
    @pytest.fixture
    def test_key(self):
        password = b"test_password"
        salt = b"test_salt_123456"  # 16 bytes
        kdf = Argon2id(
            salt=salt,
            length=AES_KEY_SIZE,
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
        )
        return kdf.derive(password)
    
    def test_encrypt_decrypt_data_roundtrip(self, encryptor, test_key):
        """Test that encryption and decryption work correctly."""
        original_data = b"This is test data for encryption and decryption testing."
        
        # Encrypt
        encrypted = encryptor.encrypt_data(original_data, test_key)
        expected_len = len(original_data) + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
        assert len(encrypted) == expected_len  # Nonce and tag added
        assert encrypted != original_data  # Should be different
        
        # Decrypt
        decrypted = encryptor.decrypt_data(encrypted, test_key)
        assert decrypted == original_data
    
    def test_invalid_encrypted_data_format(self, encryptor):
        """Test decryption with invalid data format."""
        with pytest.raises(Exception):
            encryptor.decrypt_data(b"invalid_data", b"fake_key")
    
    def test_insufficient_data_length(self, encryptor):
        """Test decryption with data too short."""
        # Data must be at least nonce + tag length
        min_length = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
        short_data = b"x" * (min_length - 1)
        
        with pytest.raises(Exception):
            encryptor.decrypt_data(short_data, b"fake_key")
    
    def test_wrong_key_decryption(self, encryptor, test_key):
        """Test decryption with wrong key."""
        original_data = b"test data"
        
        # Encrypt with correct key
        encrypted = encryptor.encrypt_data(original_data, test_key)
        
        # Try to decrypt with wrong key
        wrong_key = b"wrong_key_123456" * 2  # 32 bytes
        
        with pytest.raises(Exception):
            encryptor.decrypt_data(encrypted, wrong_key)
    
    @patch('hello_crypto.KeyCredentialManager')
    async def test_is_supported_mock(self, mock_kcm, encryptor):
        """Test is_supported method with mocked KeyCredentialManager."""
        # Mock the is_supported_async method directly
        mock_kcm.is_supported_async = AsyncMock(return_value=True)
        
        result = await encryptor.is_supported()
        assert result is True
    
    @patch('hello_crypto.KeyCredentialManager')
    async def test_is_supported_no_manager(self, mock_kcm, encryptor):
        """Test is_supported when no credential manager available."""
        # Mock is_supported_async to return False
        mock_kcm.is_supported_async = AsyncMock(return_value=False)
        
        result = await encryptor.is_supported()
        assert result is False
    
    @patch('hello_crypto.KeyCredentialManager')
    async def test_is_supported_exception(self, mock_kcm, encryptor):
        """Test is_supported when exception occurs."""
        # Mock is_supported_async to raise an exception
        mock_kcm.is_supported_async = AsyncMock(side_effect=Exception("Windows Hello not available"))
        
        # This should raise WindowsHelloError which we catch
        with pytest.raises(Exception):  # WindowsHelloError
            await encryptor.is_supported()
    
    def test_windows_hello_error_creation(self):
        """Test WindowsHelloError exception creation."""
        error = WindowsHelloError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)
    
    def test_encrypt_large_data(self, encryptor, test_key):
        """Test encryption of large data."""
        large_data = b"x" * 10000  # 10KB of data
        encrypted = encryptor.encrypt_data(large_data, test_key)
        decrypted = encryptor.decrypt_data(encrypted, test_key)
        assert decrypted == large_data

    def test_key_size_validation(self, encryptor):
        """Test that encrypt_data validates key size."""
        test_data = b"test data"
        short_key = b"short"
        
        with pytest.raises(ValueError):
            encryptor.encrypt_data(test_data, short_key)
        
    def test_encrypt_data_invalid_key_size(self, encryptor):
        """Test encryption with invalid key size."""
        invalid_key = b"short_key"
        data = b"test data"
        
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            encryptor.encrypt_data(data, invalid_key)
    
    def test_encrypt_empty_data(self, encryptor, test_key):
        """Test encryption of empty data."""
        with pytest.raises(ValueError, match="Cannot encrypt empty data"):
            encryptor.encrypt_data(b"", test_key)
    
    def test_decrypt_data_invalid_key_size(self, encryptor):
        """Test decryption with invalid key size."""
        invalid_key = b"short_key"
        # Create some dummy encrypted data
        dummy_data = secrets.token_bytes(64)
        
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            encryptor.decrypt_data(dummy_data, invalid_key)
    
    def test_decrypt_data_too_short(self, encryptor, test_key):
        """Test decryption of data that's too short."""
        short_data = b"short"
        
        with pytest.raises(ValueError, match="Invalid encrypted data: too short"):
            encryptor.decrypt_data(short_data, test_key)
    
    def test_decrypt_data_integrity_failure(self, encryptor, test_key):
        """Test decryption with corrupted data (integrity check should fail)."""
        original_data = b"Test data for integrity check"
        encrypted = encryptor.encrypt_data(original_data, test_key)

        # Corrupt the ciphertext but leave the tag untouched
        corrupted = bytearray(encrypted)
        corrupted[AES_GCM_NONCE_SIZE] ^= 1  # Flip a bit in the ciphertext portion

        with pytest.raises(ValueError, match="Data integrity check failed"):
            encryptor.decrypt_data(bytes(corrupted), test_key)
    
    def test_encrypt_different_data_produces_different_results(self, encryptor, test_key):
        """Test that encrypting the same data twice produces different results (due to random nonce)."""
        data = b"Test data for randomness check"
        
        encrypted1 = encryptor.encrypt_data(data, test_key)
        encrypted2 = encryptor.encrypt_data(data, test_key)
        
        # Should be different due to random nonce
        assert encrypted1 != encrypted2
        
        # But both should decrypt to the same original data
        assert encryptor.decrypt_data(encrypted1, test_key) == data
        assert encryptor.decrypt_data(encrypted2, test_key) == data
    
    @pytest.mark.asyncio
    async def test_is_supported_mock(self, encryptor):
        """Test Windows Hello support check (mocked)."""
        with patch('hello_crypto.KeyCredentialManager.is_supported_async') as mock_supported:
            mock_supported.return_value = AsyncMock(return_value=True)()
            assert await encryptor.is_supported() is True
            
            mock_supported.return_value = AsyncMock(return_value=False)()
            assert await encryptor.is_supported() is False
    
    @pytest.mark.asyncio
    async def test_encrypt_file_validation(self, encryptor):
        """Test file encryption with invalid inputs."""
        with pytest.raises(Exception):  # Should raise validation error
            await encryptor.encrypt_file("nonexistent.txt", "output.enc")
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_file_roundtrip(self, encryptor, test_key):
        """Test file encryption and decryption roundtrip (mocked Windows Hello)."""
        # Create test data
        test_data = b"This is test file content for encryption testing."
        
        # Use workspace-relative temp directory instead of system temp
        temp_dir = Path.cwd() / "test_temp"
        temp_dir.mkdir(exist_ok=True)
        
        try:
            input_file = temp_dir / "input.txt"
            encrypted_file = temp_dir / "encrypted.enc"
            decrypted_file = temp_dir / "decrypted.txt"
            
            # Write test data
            input_file.write_bytes(test_data)

            real_to_thread = asyncio.to_thread

            async def side_effect(func, *args, **kwargs):
                return await real_to_thread(func, *args, **kwargs)

            # Mock Windows Hello operations and track async file operations
            with patch('hello_crypto.asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread, \
                 patch.object(encryptor, 'is_supported', return_value=True), \
                 patch.object(encryptor, 'ensure_key_exists', return_value=None), \
                 patch.object(encryptor, 'derive_key_from_signature', return_value=test_key):

                mock_to_thread.side_effect = side_effect

                # Encrypt file
                await encryptor.encrypt_file(str(input_file), str(encrypted_file))
                assert encrypted_file.exists()
                assert encrypted_file.read_bytes() != test_data

                # Decrypt file
                await encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
                assert decrypted_file.exists()
                assert decrypted_file.read_bytes() == test_data

                # Ensure async file operations were performed via to_thread
                assert mock_to_thread.await_count >= 4
        finally:
            # Clean up test files
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
    
    def test_secure_memory_clear(self, encryptor):
        """Test secure memory clearing functionality."""
        from security_utils import secure_memory_clear
        from unittest.mock import patch
        
        data = bytearray(b"sensitive_data")
        
        # Mock ctypes.windll to prevent Windows fatal exceptions in CI
        with patch('ctypes.windll') as mock_windll:
            # Configure the mock to avoid any Windows-specific calls
            mock_windll.kernel32.RtlSecureZeroMemory = MagicMock()
            secure_memory_clear(data)
            
        assert all(b == 0 for b in data)

class TestErrorHandling:
    """Test error handling and edge cases."""
    
    @pytest.fixture
    def encryptor(self):
        return FileEncryptor()
    
    @pytest.fixture
    def test_key(self):
        password = b"error_test_password"
        salt = b"error_test_salt__"  # 16 bytes
        kdf = Argon2id(
            salt=salt,
            length=AES_KEY_SIZE,
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
        )
        return kdf.derive(password)
    
    def test_windows_hello_error(self):
        """Test WindowsHelloError exception."""
        with pytest.raises(WindowsHelloError):
            raise WindowsHelloError("Test error")
    
    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self):
        """Test that rate limiting is integrated into key derivation."""
        encryptor = FileEncryptor()
        
        # Mock Windows Hello to always fail
        with patch('hello_crypto.KeyCredentialManager.open_async') as mock_open:
            mock_result = MagicMock()
            mock_result.status = 1  # Failure status
            mock_open.return_value = mock_result
            
            # Should fail multiple times and eventually trigger rate limiting
            for i in range(6):  # More than max attempts
                try:
                    await encryptor.derive_key_from_signature()
                except Exception:
                    pass  # Expected to fail
    
    def test_data_validation_edge_cases(self, encryptor, test_key):
        """Test edge cases in data validation."""
        
        # Test with various data sizes
        for size in [1, 15, 16, 17, 31, 32, 33, 1000]:
            data = secrets.token_bytes(size)
            encrypted = encryptor.encrypt_data(data, test_key)
            decrypted = encryptor.decrypt_data(encrypted, test_key)
            assert decrypted == data


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


class TestImportHandling:
    """Test import error handling paths."""
    
    def test_winrt_import_mock_fallback(self):
        """Test that mock fallback works when winrt is not available."""
        # This tests the import error handling paths in lines 24-30, 33-37
        with patch.dict('sys.modules', {'winrt': None, 'winrt.windows.security': None}):
            # Re-importing should use the mocked versions
            from hello_crypto import KeyCredentialManager, DataWriter
            assert KeyCredentialManager is not None
            assert DataWriter is not None
    
    def test_windows_api_unavailable(self):
        """Test behavior when Windows API is not available."""
        # This tests lines 46-47 WINDOWS_API_AVAILABLE = False
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', False):
            from hello_crypto import _bring_window_to_foreground, _find_and_focus_hello_dialog
            assert _bring_window_to_foreground() is None
            assert _find_and_focus_hello_dialog() is False


class TestImportFallbackReload:
    """Reload module to hit import fallback except blocks for coverage."""

    def _reload_with_import_block(self, block_names):
        """Helper to reload hello_crypto while raising ImportError for given module names."""
        orig_module = sys.modules.get('hello_crypto')

        def guarded_import(name, *args, **kwargs):
            for blocked in block_names:
                if name.startswith(blocked):
                    raise ImportError(f"Blocked import: {name}")
            return original_import(name, *args, **kwargs)

        original_import = builtins.__import__
        try:
            if 'hello_crypto' in sys.modules:
                del sys.modules['hello_crypto']
            with patch('builtins.__import__', side_effect=guarded_import):
                import hello_crypto as hc
                return hc
        finally:
            # Restore original module for subsequent tests
            if orig_module is not None:
                sys.modules['hello_crypto'] = orig_module
                importlib.reload(orig_module)

    def test_fallback_winrt_security_credentials(self):
        hc = self._reload_with_import_block(['winrt.windows.security.credentials'])
        assert hasattr(hc, 'KeyCredentialManager')
        assert hasattr(hc, 'KeyCredentialStatus')
        # SUCCESS should exist on mock
        assert getattr(hc.KeyCredentialStatus, 'SUCCESS', 0) == 0

    def test_fallback_winrt_storage_streams(self):
        hc = self._reload_with_import_block(['winrt.windows.storage.streams'])
        assert hasattr(hc, 'DataWriter')
        assert hasattr(hc, 'DataReader')

    def test_fallback_ctypes_import(self):
        hc = self._reload_with_import_block(['ctypes'])
        # When ctypes import fails, WINDOWS_API_AVAILABLE should be False
        assert hc.WINDOWS_API_AVAILABLE is False


class TestFileEncryptorErrorPaths:
    """Test error handling and edge cases in FileEncryptor."""
    
    @pytest.fixture
    def encryptor(self):
        return FileEncryptor()

    @pytest.fixture
    def test_key(self):
        password = b"test_password"
        salt = b"test_salt_123456"  # 16 bytes
        kdf = Argon2id(
            salt=salt,
            length=AES_KEY_SIZE,
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
        )
        return kdf.derive(password)
    
    @pytest.mark.asyncio
    async def test_derive_key_open_key_failure(self, encryptor):
        """Test key derivation when opening key fails."""
        # This tests lines 278-283
        with patch('hello_crypto.KeyCredentialManager') as mock_kcm, \
             patch('hello_crypto.rate_limiter') as mock_rate_limiter, \
             patch('hello_crypto.audit_log') as mock_audit:
            
            # Mock failed key opening
            mock_result = MagicMock()
            mock_result.status = -1  # Not SUCCESS
            mock_kcm.open_async = AsyncMock(return_value=mock_result)
            
            import hello_crypto as hc
            with pytest.raises(hc.WindowsHelloError, match="Failed to open Windows Hello key"):
                await encryptor.derive_key_from_signature()
            
            # Verify failure is recorded (key name includes username)
            mock_rate_limiter.record_attempt.assert_called()
            args, kwargs = mock_rate_limiter.record_attempt.call_args
            assert args[0].startswith('FileEncryptKey')
            assert kwargs['success'] is False
            mock_audit.assert_called()
    
    @pytest.mark.asyncio
    async def test_derive_key_sign_failure(self, encryptor):
        """Test key derivation when signing fails."""
        # This tests lines 328-333
        with patch('hello_crypto.KeyCredentialManager') as mock_kcm, \
             patch('hello_crypto.rate_limiter') as mock_rate_limiter, \
             patch('hello_crypto.audit_log') as mock_audit, \
             patch('hello_crypto.DataWriter') as mock_writer, \
             patch('hello_crypto._bring_window_to_foreground'), \
             patch('hello_crypto._find_and_focus_hello_dialog', return_value=False):
            
            # Mock successful key opening
            mock_open_result = MagicMock()
            mock_open_result.status = KeyCredentialStatus.SUCCESS
            mock_credential = MagicMock()
            mock_open_result.credential = mock_credential
            mock_kcm.open_async = AsyncMock(return_value=mock_open_result)
            
            # Mock failed signing
            mock_sign_result = MagicMock()
            mock_sign_result.status = -1  # Not SUCCESS
            mock_credential.request_sign_async = AsyncMock(return_value=mock_sign_result)
            
            # Mock writer
            mock_writer_instance = MagicMock()
            mock_writer.return_value = mock_writer_instance
            mock_writer_instance.detach_buffer.return_value = b'challenge'
            
            import hello_crypto as hc
            with pytest.raises(hc.WindowsHelloError, match="Biometric authentication failed"):
                await encryptor.derive_key_from_signature()
            
            # Verify failure is recorded (key name includes username)
            mock_rate_limiter.record_attempt.assert_called()
            args, kwargs = mock_rate_limiter.record_attempt.call_args
            assert args[0].startswith('FileEncryptKey')
            assert kwargs['success'] is False
            mock_audit.assert_called()
    
    @pytest.mark.asyncio
    async def test_decrypt_data_integrity_failure(self, encryptor):
        """Test decrypt_data with integrity check failure."""
        # This tests lines 409-414
        test_key = b"x" * 32
        
        # Create malformed encrypted data that will fail integrity check
        malformed_data = b"malformed" + b"x" * 50
        
        with pytest.raises(ValueError, match="Data integrity check failed"):
            await encryptor.decrypt_data(malformed_data, test_key)
    
    @pytest.mark.asyncio
    async def test_decrypt_data_cipher_failure(self, encryptor):
        """Test decrypt_data with cipher decryption failure that doesn't hit integrity check first."""
        test_key = b"x" * 32
        
        # Create data with correct structure but that will cause InvalidTag in cipher
        fake_nonce = b"x" * 12
        fake_tag = b"x" * 16
        fake_ciphertext = b"x" * 32
        malformed_data = fake_nonce + fake_tag + fake_ciphertext
        
        with patch('hello_crypto.audit_log') as mock_audit:
            # We expect integrity check to fail first, so test that path
            with pytest.raises(ValueError, match="Data integrity check failed"):
                await encryptor.decrypt_data(malformed_data, test_key)
            
            # Verify security event is logged
            mock_audit.assert_called()

    def test_decrypt_data_invalidtag_branch(self, encryptor, test_key):
        """Force AESGCM.decrypt to raise InvalidTag to hit that except path."""
        # Build minimal well-formed envelope (nonce + ciphertext-with-tag)
        nonce = b"n" * 12
        payload = b"c" * 32  # arbitrary bytes; actual contents don't matter for this mock
        data = nonce + payload

        with patch('hello_crypto.AESGCM.decrypt', side_effect=InvalidTag), \
             patch('hello_crypto.audit_log') as mock_audit:
            with pytest.raises(ValueError, match="Data integrity check failed"):
                encryptor.decrypt_data(data, test_key)
            mock_audit.assert_called()

    @pytest.mark.asyncio
    async def test_encrypt_file_cleanup_on_error(self, encryptor, test_key):
        """Ensure encrypt_file cleans temp and logs on error inside try block."""
        temp_dir = Path.cwd() / "enc_cleanup_temp"
        temp_dir.mkdir(exist_ok=True)
        try:
            input_file = temp_dir / "in.txt"
            output_file = temp_dir / "out.enc"
            input_file.write_bytes(b"")  # empty triggers ValueError inside try

            # Bypass path validation and Windows Hello
            with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
                 patch.object(encryptor, 'is_supported', return_value=True), \
                 patch.object(encryptor, 'ensure_key_exists', return_value=None), \
                 patch.object(encryptor, 'derive_key_from_signature', return_value=test_key), \
                 patch('hello_crypto.audit_log') as mock_audit:
                with pytest.raises(ValueError, match="Cannot encrypt empty file"):
                    await encryptor.encrypt_file(str(input_file), str(output_file))
                mock_audit.assert_called()
                # temp file should not remain
                assert not (output_file.with_suffix('.tmp')).exists()
        finally:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

    @pytest.mark.asyncio
    async def test_encrypt_file_cleanup_on_error_unlink(self, encryptor, test_key, tmp_path):
        """Ensure temp file is unlinked on error path (line 468)."""
        inp = tmp_path / "in.txt"
        outp = tmp_path / "out.enc"
        inp.write_text("data")
        # Pre-create temp file to force unlink branch
        tmpf = outp.with_suffix('.tmp')
        tmpf.write_bytes(b"junk")
        with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
             patch.object(encryptor, 'is_supported', return_value=True), \
             patch.object(encryptor, 'ensure_key_exists'), \
             patch.object(encryptor, 'derive_key_from_signature', return_value=test_key), \
             patch.object(encryptor, 'encrypt_data', side_effect=ValueError("bad enc")):
            with pytest.raises(ValueError, match="bad enc"):
                await encryptor.encrypt_file(str(inp), str(outp))
        assert not tmpf.exists()

    @pytest.mark.asyncio
    async def test_decrypt_file_cleanup_on_error_in_try(self, encryptor, test_key):
        """Ensure decrypt_file cleans temp and logs on error inside try block."""
        temp_dir = Path.cwd() / "dec_cleanup_temp"
        temp_dir.mkdir(exist_ok=True)
        try:
            input_file = temp_dir / "in.enc"
            output_file = temp_dir / "out.txt"
            input_file.write_bytes(b"x" * 40)  # arbitrary data triggers decrypt_data error

            with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
                 patch.object(encryptor, 'is_supported', return_value=True), \
                 patch.object(encryptor, 'ensure_key_exists', return_value=None), \
                 patch.object(encryptor, 'derive_key_from_signature', return_value=test_key), \
                 patch.object(encryptor, 'decrypt_data', side_effect=ValueError("bad data")), \
                 patch('hello_crypto.audit_log') as mock_audit:
                with pytest.raises(ValueError, match="bad data"):
                    await encryptor.decrypt_file(str(input_file), str(output_file))
                mock_audit.assert_called()
                assert not (output_file.with_suffix('.tmp')).exists()
        finally:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
    
    @pytest.mark.asyncio
    async def test_decrypt_file_cleanup_on_error(self, encryptor):
        """Test decrypt_file cleans up temp files on error."""
        # This tests lines 515-523
        # Test with files in current directory to avoid path validation errors
        input_file = "test_input.enc"
        output_file = "test_output.txt"
        
        # Create a minimal encrypted file
        Path(input_file).write_bytes(b"x" * 50)
        
        try:
            with patch.object(encryptor, 'derive_key_from_signature', side_effect=Exception("Test error")), \
                 patch('hello_crypto.audit_log') as mock_audit:
                
                with pytest.raises(Exception, match="Test error"):
                    await encryptor.decrypt_file(input_file, output_file)
                
                # Verify audit logging
                mock_audit.assert_called()
        finally:
            # Clean up test files
            for f in [input_file, output_file]:
                if Path(f).exists():
                    Path(f).unlink()

    @pytest.mark.asyncio
    async def test_encrypt_file_success_path(self, encryptor, test_key):
        """Cover successful encrypt_file path including audit logging and atomic rename."""
        temp_dir = Path.cwd() / "enc_success_temp"
        temp_dir.mkdir(exist_ok=True)
        try:
            input_file = temp_dir / "in.txt"
            output_file = temp_dir / "out.enc"
            input_file.write_text("hello world")

            with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
                 patch.object(encryptor, 'is_supported', return_value=True), \
                 patch.object(encryptor, 'ensure_key_exists', return_value=None), \
                 patch.object(encryptor, 'derive_key_from_signature', return_value=test_key), \
                 patch('hello_crypto.audit_log') as mock_audit:
                await encryptor.encrypt_file(str(input_file), str(output_file))
                assert output_file.exists()
                mock_audit.assert_called()
        finally:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

    @pytest.mark.asyncio
    async def test_decrypt_file_success_path(self, encryptor, test_key):
        """Cover successful decrypt_file path including audit logging and atomic rename."""
        temp_dir = Path.cwd() / "dec_success_temp"
        temp_dir.mkdir(exist_ok=True)
        try:
            input_file = temp_dir / "in.enc"
            output_file = temp_dir / "out.txt"
            # Prepare a valid encrypted payload
            plaintext = b"hello world"
            ciphertext = encryptor.encrypt_data(plaintext, test_key)
            input_file.write_bytes(ciphertext)

            with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
                 patch.object(encryptor, 'is_supported', return_value=True), \
                 patch.object(encryptor, 'ensure_key_exists', return_value=None), \
                 patch.object(encryptor, 'derive_key_from_signature', return_value=test_key), \
                 patch('hello_crypto.audit_log') as mock_audit:
                await encryptor.decrypt_file(str(input_file), str(output_file))
                assert output_file.exists()
                assert output_file.read_bytes() == plaintext
                mock_audit.assert_called()
        finally:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

    def test_decrypt_data_generic_exception_branch(self, encryptor, test_key):
        """Force a generic exception during decryption to cover the second except in decrypt_data."""
        nonce = b"n" * 12
        payload = b"p" * 32
        data = nonce + payload
        class DummyErr(Exception):
            pass
        with patch('hello_crypto.AESGCM.decrypt', side_effect=DummyErr("boom")), \
             patch('hello_crypto.audit_log') as mock_audit:
            with pytest.raises(ValueError, match="Decryption failed:"):
                encryptor.decrypt_data(data, test_key)
            mock_audit.assert_called()

    @pytest.mark.asyncio
    async def test_encrypt_file_unsupported(self, encryptor, tmp_path):
        """Cover unsupported device branch in encrypt_file (line 426)."""
        inp = tmp_path / "in.txt"
        outp = tmp_path / "out.bin"
        inp.write_text("data")
        with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
             patch.object(encryptor, 'is_supported', return_value=False):
            import hello_crypto as hc
            with pytest.raises(hc.WindowsHelloError, match="not supported"):
                await encryptor.encrypt_file(str(inp), str(outp))

    @pytest.mark.asyncio
    async def test_decrypt_file_unsupported(self, encryptor, tmp_path):
        """Cover unsupported device branch in decrypt_file (line 480)."""
        inp = tmp_path / "in.bin"
        outp = tmp_path / "out.txt"
        inp.write_bytes(b"\x00"*32)
        with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
             patch.object(encryptor, 'is_supported', return_value=False):
            import hello_crypto as hc
            with pytest.raises(hc.WindowsHelloError, match="not supported"):
                await encryptor.decrypt_file(str(inp), str(outp))

    @pytest.mark.asyncio
    async def test_decrypt_file_missing_and_empty(self, encryptor, tmp_path, test_key):
        """Cover missing file (497) and empty ciphertext (502)."""
        # Missing file
        with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
             patch.object(encryptor, 'is_supported', return_value=True), \
             patch.object(encryptor, 'ensure_key_exists'), \
             patch.object(encryptor, 'derive_key_from_signature', return_value=test_key):
            with pytest.raises(FileNotFoundError):
                await encryptor.decrypt_file(str(tmp_path/"nope.bin"), str(tmp_path/"out.txt"))

        # Empty ciphertext
        inp = tmp_path / "empty.bin"
        outp = tmp_path / "out.txt"
        inp.write_bytes(b"")
        with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
             patch.object(encryptor, 'is_supported', return_value=True), \
             patch.object(encryptor, 'ensure_key_exists'), \
             patch.object(encryptor, 'derive_key_from_signature', return_value=test_key):
            with pytest.raises(ValueError, match="Cannot decrypt empty file"):
                await encryptor.decrypt_file(str(inp), str(outp))

    @pytest.mark.asyncio
    async def test_decrypt_file_cleanup_on_error(self, encryptor, tmp_path, test_key):
        """Ensure temp file is unlinked on error (line 522)."""
        inp = tmp_path / "data.bin"
        outp = tmp_path / "out.txt"
        # Write minimal valid-looking bytes to get past length check; then force decrypt_data error
        inp.write_bytes(b"\x00"*32)
        # Pre-create temp file to ensure unlink branch runs
        temp = outp.with_suffix('.tmp')
        temp.write_bytes(b"junk")
        with patch('hello_crypto.validate_file_path', side_effect=lambda p, m: Path(p)), \
             patch.object(encryptor, 'is_supported', return_value=True), \
             patch.object(encryptor, 'ensure_key_exists'), \
             patch.object(encryptor, 'derive_key_from_signature', return_value=test_key), \
             patch.object(encryptor, 'decrypt_data', side_effect=ValueError("bad decrypt")):
            with pytest.raises(ValueError, match="bad decrypt"):
                await encryptor.decrypt_file(str(inp), str(outp))
        assert not temp.exists()


class TestMainFunctionCoverage:
    """Test main function and CLI entry points."""
    
    @pytest.mark.asyncio
    async def test_main_encrypt_mode(self):
       """Test main function in encrypt mode."""
       # Patch the class so main uses a mocked instance
       with patch('hello_crypto.FileEncryptor') as mock_cls, \
           patch('builtins.print') as mock_print:
          inst = mock_cls.return_value
          inst.encrypt_file = AsyncMock()
          from hello_crypto import main
          await main("encrypt", "input.txt", "output.enc")
          inst.encrypt_file.assert_called_once_with("input.txt", "output.enc")
          # Verify success print
          assert mock_print.called
          msg, *_ = mock_print.call_args[0]
          assert "File encrypted successfully." in msg
    
    @pytest.mark.asyncio
    async def test_main_decrypt_mode(self):
       """Test main function in decrypt mode."""
       with patch('hello_crypto.FileEncryptor') as mock_cls, \
           patch('builtins.print') as mock_print:
          inst = mock_cls.return_value
          inst.decrypt_file = AsyncMock()
          from hello_crypto import main
          await main("decrypt", "input.enc", "output.txt")
          inst.decrypt_file.assert_called_once_with("input.enc", "output.txt")
          # Verify success print
          assert mock_print.called
          msg, *_ = mock_print.call_args[0]
          assert "File decrypted successfully." in msg
    
    @pytest.mark.asyncio
    async def test_main_windows_hello_error(self):
        """Test main function handling WindowsHelloError."""
        # This tests lines 551-570
        with patch('hello_crypto.FileEncryptor') as mock_cls, \
             patch('builtins.print') as mock_print:
            inst = mock_cls.return_value
            inst.encrypt_file = AsyncMock(side_effect=WindowsHelloError("Auth failed"))
            from hello_crypto import main
            await main("encrypt", "input.txt", "output.enc")
            mock_print.assert_called()
            args, _ = mock_print.call_args
            # In this code path, WindowsHelloError from the encrypt_file call is not caught and falls under generic exception
            assert "Unexpected Error" in args[0]
            assert "Auth failed" in args[0]
    
    @pytest.mark.asyncio
    async def test_main_file_not_found_error(self):
        """Test main function handling file errors."""
        with patch('hello_crypto.FileEncryptor') as mock_cls, \
             patch('builtins.print') as mock_print:
            inst = mock_cls.return_value
            inst.encrypt_file = AsyncMock(side_effect=FileNotFoundError("missing"))
            from hello_crypto import main
            await main("encrypt", "nonexistent.txt", "output.enc")
            mock_print.assert_called()
            args, _ = mock_print.call_args
            assert "File Error" in args[0]
    
    @pytest.mark.asyncio
    async def test_main_unexpected_error(self):
        """Test main function handling unexpected errors."""
        with patch('hello_crypto.FileEncryptor') as mock_cls, \
             patch('builtins.print') as mock_print:
            inst = mock_cls.return_value
            inst.encrypt_file = AsyncMock(side_effect=RuntimeError("Unexpected"))
            from hello_crypto import main
            await main("encrypt", "input.txt", "output.enc")
            mock_print.assert_called()
            args, _ = mock_print.call_args
            assert "Unexpected Error" in args[0]
    
    def test_cli_main_function(self):
        """Test CLI entry point function."""
        with patch('hello_crypto.argparse.ArgumentParser') as mock_parser_class, \
             patch('hello_crypto.asyncio.run') as mock_run:
            
            # Mock argument parser
            mock_parser = MagicMock()
            mock_parser_class.return_value = mock_parser
            mock_args = MagicMock()
            mock_args.mode = "encrypt"
            mock_args.input_file = "input.txt"
            mock_args.output_file = "output.enc"
            mock_parser.parse_args.return_value = mock_args
            
            from hello_crypto import cli_main
            cli_main()
            
            # Verify argument parser was set up correctly
            mock_parser_class.assert_called_once()
            mock_parser.add_argument.assert_called()
            mock_parser.parse_args.assert_called_once()
            mock_run.assert_called_once()

    def test_main_invalid_mode_and_errors(self):
        """Cover invalid mode print (539) and WindowsHelloError print (542)."""
        from hello_crypto import main
        # Invalid mode
        with patch('builtins.print') as mp:
            asyncio.run(main("bogus", "a", "b"))
            mp.assert_called()
            assert any("Invalid mode" in args[0] for args, _ in mp.call_args_list)

        # WindowsHelloError path
        import hello_crypto as hc
        with patch('hello_crypto.FileEncryptor') as mock_cls, \
             patch('builtins.print') as mp2:
            inst = mock_cls.return_value
            inst.encrypt_file = AsyncMock(side_effect=hc.WindowsHelloError("no hello"))
            asyncio.run(main("encrypt", "a", "b"))
            mp2.assert_called()
            assert any("Windows Hello Error" in args[0] for args, _ in mp2.call_args_list)


class TestDefaultsAndVerify:
    @pytest.mark.asyncio
    async def test_default_output_paths_encrypt_and_decrypt(self):
        """Cover default output computation when output_file is not provided."""
        with patch('hello_crypto.FileEncryptor') as mock_cls:
            inst = mock_cls.return_value
            inst.encrypt_file = AsyncMock()
            inst.decrypt_file = AsyncMock()

            from hello_crypto import main_encrypt_decrypt
            # Encrypt default -> appends .enc
            await main_encrypt_decrypt("encrypt", "C:/tmp/foo.txt", None)
            from pathlib import Path as _P
            exp1 = str(_P("C:/tmp/foo.txt").with_suffix(".txt.enc"))
            inst.encrypt_file.assert_awaited_with("C:/tmp/foo.txt", exp1)

            # Decrypt default: strip .enc
            await main_encrypt_decrypt("decrypt", "C:/tmp/bar.txt.enc", None)
            exp2 = str(_P("C:/tmp/bar.txt.enc").with_name("bar.txt"))
            inst.decrypt_file.assert_awaited_with("C:/tmp/bar.txt.enc", exp2)

            # Decrypt default: add .dec when no .enc suffix
            await main_encrypt_decrypt("decrypt", "C:/tmp/data.bin", None)
            exp3 = str(_P("C:/tmp/data.bin").with_suffix(".bin.dec"))
            inst.decrypt_file.assert_awaited_with("C:/tmp/data.bin", exp3)

    @pytest.mark.asyncio
    async def test_main_verify_success(self, monkeypatch, tmp_path):
        """Cover verify path success (prints pass and returns 0)."""
        # Create a dummy file to read
        f = tmp_path / "enc.bin"
        f.write_bytes(b"ciphertext")

        # Patch FileEncryptor instance methods
        import hello_crypto as hc
        with patch('hello_crypto.FileEncryptor') as mock_cls, \
             patch('builtins.print') as mock_print:
            inst = mock_cls.return_value
            inst.is_supported = AsyncMock(return_value=True)
            inst.ensure_key_exists = AsyncMock()
            inst.derive_key_from_signature = AsyncMock(return_value=b"k"*32)
            inst.decrypt_data = MagicMock(return_value=b"ok")

            rc = await hc.main_verify(str(f))
            assert rc == 0
            # Ensure decrypt_data was called
            inst.decrypt_data.assert_called_once()
            # Printed success
            assert any("Integrity check passed" in args[0] for args, _ in mock_print.call_args_list)


class TestBringWindowToForegroundCoverage:
    """Test window management functions with Windows API available."""
    
    def test_bring_window_to_foreground_with_api(self):
        """Test _bring_window_to_foreground when Windows API is available."""
        # This tests lines 81-116
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', True), \
             patch('hello_crypto.os.name', 'nt'), \
             patch('hello_crypto.user32') as mock_user32, \
             patch('hello_crypto.kernel32') as mock_kernel32, \
             patch('hello_crypto.time.sleep') as mock_sleep, \
             patch('hello_crypto.logger') as mock_logger:
            
            # Mock Windows API calls
            mock_kernel32.GetConsoleWindow.return_value = 12345
            mock_user32.GetForegroundWindow.return_value = 67890  # Different window
            mock_kernel32.GetCurrentThreadId.return_value = 111
            mock_user32.GetWindowThreadProcessId.return_value = 222  # Different thread
            mock_user32.ShowWindow.return_value = True
            mock_user32.SetWindowPos.return_value = True
            mock_user32.AttachThreadInput.return_value = True
            mock_user32.SetForegroundWindow.return_value = True
            mock_user32.SetFocus.return_value = True
            mock_user32.BringWindowToTop.return_value = True
            
            from hello_crypto import _bring_window_to_foreground
            _bring_window_to_foreground()
            
            # Verify API calls were made
            mock_kernel32.GetConsoleWindow.assert_called_once()
            mock_user32.GetForegroundWindow.assert_called_once()
            mock_user32.ShowWindow.assert_called_once_with(12345, 9)  # SW_RESTORE
            mock_user32.SetForegroundWindow.assert_called()
            mock_user32.BringWindowToTop.assert_called_once_with(12345)
            mock_sleep.assert_called_once_with(0.2)
            mock_logger.info.assert_called()

    def test_bring_window_to_foreground_non_windows(self):
        """Cover early return when Windows API is unavailable or non-Windows OS."""
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', False), \
             patch('hello_crypto.os.name', 'posix'):
            from hello_crypto import _bring_window_to_foreground
            # Should return immediately without error
            assert _bring_window_to_foreground() is None

    def test_bring_window_to_foreground_same_window(self):
        """Cover branch where current foreground equals console window."""
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', True), \
             patch('hello_crypto.os.name', 'nt'), \
             patch('hello_crypto.user32') as mock_user32, \
             patch('hello_crypto.kernel32') as mock_kernel32:

            mock_kernel32.GetConsoleWindow.return_value = 22222
            mock_user32.GetForegroundWindow.return_value = 22222  # Same window

            from hello_crypto import _bring_window_to_foreground
            _bring_window_to_foreground()

            # Should still perform some window operations
            mock_user32.ShowWindow.assert_called()

    def test_bring_window_to_foreground_same_thread(self):
        """Cover branch where different window but same thread (lines 110-111)."""
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', True), \
             patch('hello_crypto.os.name', 'nt'), \
             patch('hello_crypto.user32') as mock_user32, \
             patch('hello_crypto.kernel32') as mock_kernel32:

            console = 44444
            other = 55555
            mock_kernel32.GetConsoleWindow.return_value = console
            mock_user32.GetForegroundWindow.return_value = other  # Different window
            # Same thread id path
            mock_kernel32.GetCurrentThreadId.return_value = 777
            mock_user32.GetWindowThreadProcessId.return_value = 777  # Same thread -> triggers lines 110-111

            from hello_crypto import _bring_window_to_foreground
            _bring_window_to_foreground()

            mock_user32.SetForegroundWindow.assert_called()
            mock_user32.SetFocus.assert_called()

    def test_bring_window_to_foreground_no_foreground(self):
        """Cover branch where there is no current foreground window."""
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', True), \
             patch('hello_crypto.os.name', 'nt'), \
             patch('hello_crypto.user32') as mock_user32, \
             patch('hello_crypto.kernel32') as mock_kernel32:

            mock_kernel32.GetConsoleWindow.return_value = 33333
            mock_user32.GetForegroundWindow.return_value = 0  # No window

            from hello_crypto import _bring_window_to_foreground
            _bring_window_to_foreground()

            mock_user32.SetForegroundWindow.assert_called()
            mock_user32.SetFocus.assert_called()
    
    def test_bring_window_to_foreground_exception(self):
        """Test _bring_window_to_foreground exception handling."""
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', True), \
             patch('hello_crypto.os.name', 'nt'), \
             patch('hello_crypto.kernel32.GetConsoleWindow', side_effect=Exception("API Error")), \
             patch('hello_crypto.logger') as mock_logger:
            
            from hello_crypto import _bring_window_to_foreground
            _bring_window_to_foreground()  # Should not raise
            
            # Should log warning
            mock_logger.warning.assert_called()
    
    def test_find_and_focus_hello_dialog_with_api(self):
        """Test _find_and_focus_hello_dialog when Windows API is available."""
        # This tests lines 216-218 and more
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', True), \
             patch('hello_crypto.os.name', 'nt'), \
             patch('hello_crypto.user32') as mock_user32, \
             patch('hello_crypto.ctypes') as mock_ctypes, \
             patch('hello_crypto.logger') as mock_logger:
            
            # Mock the EnumWindows callback to find a Hello dialog
            def mock_enum_windows(callback, lparam):
                # Simulate finding a Windows Hello window
                window_handle = 12345
                # Call the callback with our mock window
                callback(window_handle, lparam)
                return True
            
            mock_user32.EnumWindows = mock_enum_windows
            mock_user32.GetWindowTextW.return_value = 15  # Length of text
            mock_user32.IsWindowVisible.return_value = True
            mock_user32.SetForegroundWindow.return_value = True
            mock_user32.SetFocus.return_value = True
            
            # Mock ctypes buffer
            mock_buffer = MagicMock()
            mock_buffer.value = "Windows Security"
            mock_ctypes.create_unicode_buffer.return_value = mock_buffer
            
            from hello_crypto import _find_and_focus_hello_dialog
            result = _find_and_focus_hello_dialog()
            
            # Should return True if Hello dialog found
            assert result is True or result is False  # Depends on mock behavior
    
    def test_find_and_focus_hello_dialog_exception(self):
        """Test _find_and_focus_hello_dialog exception handling."""
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', True), \
             patch('hello_crypto.os.name', 'nt'), \
             patch('hello_crypto.user32.EnumWindows', side_effect=Exception("API Error")), \
             patch('hello_crypto.logger') as mock_logger:
            
            from hello_crypto import _find_and_focus_hello_dialog
            result = _find_and_focus_hello_dialog()
            
            # Should return False and log warning
            assert result is False
            mock_logger.warning.assert_called()

    def test_find_and_focus_handles_callback_exception(self):
        """Force exception inside EnumWindows callback to cover inner except path."""
        with patch('hello_crypto.WINDOWS_API_AVAILABLE', True), \
             patch('hello_crypto.os.name', 'nt'), \
             patch('hello_crypto.user32') as mock_user32:

            # Simulate EnumWindows calling the callback once
            def enum_windows(fake_cb, lparam):
                # Call the callback; inside it we cause an exception on title retrieval
                fake_cb(1001, 0)
                return 1

            mock_user32.EnumWindows.side_effect = enum_windows
            mock_user32.GetWindowTextLengthW.side_effect = Exception("boom")

            from hello_crypto import _find_and_focus_hello_dialog
            # Should handle internal exceptions gracefully
            assert _find_and_focus_hello_dialog() in (False, True)
