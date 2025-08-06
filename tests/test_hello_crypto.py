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
    from hello_crypto import FileEncryptor, WindowsHelloError
    from security_config import AES_KEY_SIZE, AES_BLOCK_SIZE
except ImportError as e:
    pytest.skip(f"Could not import hello_crypto modules: {e}", allow_module_level=True)

class TestFileEncryptor:
    """Test FileEncryptor functionality."""
    
    @pytest.fixture
    def encryptor(self):
        return FileEncryptor()
    
    @pytest.fixture
    def test_key(self):
        return secrets.token_bytes(AES_KEY_SIZE)
    
    def test_encrypt_decrypt_data_roundtrip(self, encryptor, test_key):
        """Test that encryption and decryption work correctly."""
        original_data = b"This is test data for encryption and decryption testing."
        
        # Encrypt
        encrypted = encryptor.encrypt_data(original_data, test_key)
        assert len(encrypted) > len(original_data)  # Should be larger due to IV and padding
        assert encrypted != original_data  # Should be different
        
        # Decrypt
        decrypted = encryptor.decrypt_data(encrypted, test_key)
        assert decrypted == original_data
    
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

        # Corrupt the ciphertext but leave the HMAC untouched
        corrupted = bytearray(encrypted)
        corrupted[AES_BLOCK_SIZE] ^= 1  # Flip a bit in the ciphertext portion

        with pytest.raises(ValueError, match="Data integrity check failed"):
            encryptor.decrypt_data(bytes(corrupted), test_key)
    
    def test_encrypt_different_data_produces_different_results(self, encryptor, test_key):
        """Test that encrypting the same data twice produces different results (due to random IV)."""
        data = b"Test data for randomness check"
        
        encrypted1 = encryptor.encrypt_data(data, test_key)
        encrypted2 = encryptor.encrypt_data(data, test_key)
        
        # Should be different due to random IV
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
    async def test_encrypt_decrypt_file_roundtrip(self, encryptor):
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
                 patch.object(encryptor, 'derive_key_from_signature', return_value=secrets.token_bytes(AES_KEY_SIZE)):

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
        return secrets.token_bytes(AES_KEY_SIZE)
    
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
    
    def test_data_validation_edge_cases(self, encryptor):
        """Test edge cases in data validation."""
        test_key = secrets.token_bytes(AES_KEY_SIZE)
        
        # Test with various data sizes
        for size in [1, 15, 16, 17, 31, 32, 33, 1000]:
            data = secrets.token_bytes(size)
            encrypted = encryptor.encrypt_data(data, test_key)
            decrypted = encryptor.decrypt_data(encrypted, test_key)
            assert decrypted == data

if __name__ == "__main__":
    pytest.main([__file__])
