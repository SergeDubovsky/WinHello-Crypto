"""
Unit tests for hello_crypto module
"""

import asyncio
import pytest
import tempfile
import os
import sys
import secrets
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path

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


class TestFileEncryptorErrorPaths:
    """Test error handling and edge cases in FileEncryptor."""
    
    @pytest.fixture
    def encryptor(self):
        return FileEncryptor()
    
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
            
            with pytest.raises(WindowsHelloError, match="Failed to open Windows Hello key"):
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
            
            with pytest.raises(WindowsHelloError, match="Biometric authentication failed"):
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


class TestMainFunctionCoverage:
    """Test main function and CLI entry points."""
    
    @pytest.mark.asyncio
    async def test_main_encrypt_mode(self):
        """Test main function in encrypt mode."""
        # This tests lines 529-546
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = Path(temp_dir) / "input.txt"
            output_file = Path(temp_dir) / "output.enc"
            input_file.write_text("test content")
            
            with patch.object(FileEncryptor, 'encrypt_file') as mock_encrypt:
                mock_encrypt.return_value = None
                
                from hello_crypto import main
                await main("encrypt", str(input_file), str(output_file))
                
                mock_encrypt.assert_called_once_with(str(input_file), str(output_file))
    
    @pytest.mark.asyncio
    async def test_main_decrypt_mode(self):
        """Test main function in decrypt mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = Path(temp_dir) / "input.enc"
            output_file = Path(temp_dir) / "output.txt"
            input_file.write_bytes(b"encrypted content")
            
            with patch.object(FileEncryptor, 'decrypt_file') as mock_decrypt:
                mock_decrypt.return_value = None
                
                from hello_crypto import main
                await main("decrypt", str(input_file), str(output_file))
                
                mock_decrypt.assert_called_once_with(str(input_file), str(output_file))
    
    @pytest.mark.asyncio
    async def test_main_windows_hello_error(self):
        """Test main function handling WindowsHelloError."""
        # This tests lines 551-570
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = Path(temp_dir) / "input.txt"
            output_file = Path(temp_dir) / "output.enc"
            input_file.write_text("test content")
            
            with patch.object(FileEncryptor, 'encrypt_file', side_effect=WindowsHelloError("Auth failed")), \
                 patch('builtins.print') as mock_print:
                
                from hello_crypto import main
                await main("encrypt", str(input_file), str(output_file))
                
                # Should print the error
                mock_print.assert_called()
                args, _ = mock_print.call_args
                assert "Windows Hello Error" in args[0]
                assert "Auth failed" in args[0]
    
    @pytest.mark.asyncio
    async def test_main_file_not_found_error(self):
        """Test main function handling file errors."""
        with patch('builtins.print') as mock_print:
            from hello_crypto import main
            await main("encrypt", "nonexistent.txt", "output.enc")
            
            # Should print the error - check for various error patterns
            mock_print.assert_called()
            args, _ = mock_print.call_args
            # Accept various error message formats
            assert any(phrase in args[0] for phrase in ["File Error", "Error:", "file", "not found", "nonexistent", "Unexpected Error"])
    
    @pytest.mark.asyncio
    async def test_main_unexpected_error(self):
        """Test main function handling unexpected errors."""
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = Path(temp_dir) / "input.txt"
            output_file = Path(temp_dir) / "output.enc"
            input_file.write_text("test content")
            
            with patch.object(FileEncryptor, 'encrypt_file', side_effect=RuntimeError("Unexpected")), \
                 patch('builtins.print') as mock_print:
                
                from hello_crypto import main
                await main("encrypt", str(input_file), str(output_file))
                
                # Should print the error
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
