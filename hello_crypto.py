import argparse
import asyncio
import hashlib
import logging
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

try:
    from winrt.windows.security.credentials import (
        KeyCredentialManager, 
        KeyCredentialCreationOption,
        KeyCredentialStatus
    )
except ImportError:
    # Mock for non-Windows environments or missing winrt
    from unittest.mock import MagicMock
    KeyCredentialManager = MagicMock()
    KeyCredentialCreationOption = MagicMock()
    KeyCredentialStatus = MagicMock()
    KeyCredentialStatus.SUCCESS = 0
try:
    from winrt.windows.storage.streams import DataWriter, DataReader
except ImportError:
    # Mock for non-Windows environments
    from unittest.mock import MagicMock
    DataWriter = MagicMock()
    DataReader = MagicMock()

# Import security utilities
from security_utils import (
    SecurityError, ValidationError, RateLimitError, rate_limiter,
    audit_log, validate_file_path, secure_memory_clear, 
    sanitize_error_message, constant_time_compare
)
from security_config import (
    AES_BLOCK_SIZE, AES_KEY_SIZE, PBKDF2_ITERATIONS, 
    KEY_NAME_FILE, CHALLENGE_MESSAGE, SECURITY_EVENTS
)

# Configure logging with security considerations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler('winhello_crypto.log')
    ]
)
logger = logging.getLogger(__name__)

# Disable debug logging in production to prevent sensitive data leakage
if os.getenv('WINHELLO_DEBUG') != '1':
    logging.getLogger().setLevel(logging.INFO)

class WindowsHelloError(Exception):
    """Custom exception for Windows Hello operations."""
    pass


class FileEncryptor:
    """Windows Hello-based file encryption and decryption with enhanced security."""
    
    def __init__(self, key_name: str = KEY_NAME_FILE, challenge: str = CHALLENGE_MESSAGE):
        self.key_name = key_name
        self.challenge = challenge
        self._auth_attempts = 0
        self._last_auth_attempt = 0.0
    
    async def is_supported(self) -> bool:
        """Check if Windows Hello is supported on this device."""
        try:
            return await KeyCredentialManager.is_supported_async()
        except Exception as e:
            raise WindowsHelloError(f"Failed to check Windows Hello support: {e}")
    
    async def ensure_key_exists(self) -> None:
        """Ensure the Windows Hello key pair exists."""
        try:
            open_result = await KeyCredentialManager.open_async(self.key_name)
            if open_result.status != KeyCredentialStatus.SUCCESS:
                create_result = await KeyCredentialManager.request_create_async(
                    self.key_name, 
                    KeyCredentialCreationOption.FAIL_IF_EXISTS
                )
                if create_result.status != KeyCredentialStatus.SUCCESS:
                    raise WindowsHelloError(f"Failed to create key: {create_result.status}")
        except Exception as e:
            if "key pair exists" not in str(e).lower():
                raise WindowsHelloError(f"Failed to ensure key exists: {e}")
    
    async def _extract_signature_bytes(self, buffer_data) -> bytes:
        """Extract bytes from Windows Runtime IBuffer."""
        try:
            # Method 1: Direct conversion
            return bytes(buffer_data)
        except (TypeError, AttributeError):
            try:
                # Method 2: Use DataReader
                reader = DataReader.from_buffer(buffer_data)
                return reader.read_bytes(buffer_data.length)
            except Exception as e:
                raise WindowsHelloError(f"Failed to extract signature bytes: {e}")
    
    async def derive_key_from_signature(self) -> bytes:
        """Derive encryption key from Windows Hello signature with enhanced security."""
        auth_identifier = f"{self.key_name}_{os.getenv('USERNAME', 'unknown')}"
        
        try:
            # Check rate limiting
            rate_limiter.check_rate_limit(auth_identifier)
            
            logger.info(f"Deriving encryption key using Windows Hello for key: {self.key_name}")
            
            # Open the key
            open_result = await KeyCredentialManager.open_async(self.key_name)
            if open_result.status != KeyCredentialStatus.SUCCESS:
                rate_limiter.record_attempt(auth_identifier, success=False)
                audit_log(SECURITY_EVENTS['AUTH_FAILURE'], {
                    'key_name': self.key_name,
                    'error': 'failed_to_open_key'
                })
                raise WindowsHelloError("Failed to open Windows Hello key")

            # Prepare challenge buffer with deterministic challenge for key derivation
            # but include user context for security
            writer = DataWriter()
            # Use deterministic challenge for consistent key derivation
            deterministic_challenge = f"{self.challenge}:{self.key_name}:{os.getenv('USERNAME', 'user')}"
            writer.write_string(deterministic_challenge)
            challenge_buffer = writer.detach_buffer()

            # Sign with biometric authentication
            logger.info("Requesting Windows Hello authentication...")
            sign_result = await open_result.credential.request_sign_async(challenge_buffer)
            
            if sign_result.status != KeyCredentialStatus.SUCCESS:
                rate_limiter.record_attempt(auth_identifier, success=False)
                audit_log(SECURITY_EVENTS['AUTH_FAILURE'], {
                    'key_name': self.key_name,
                    'error': 'biometric_auth_failed'
                })
                raise WindowsHelloError("Biometric authentication failed or was cancelled")

            # Extract signature and derive key with PBKDF2
            signature = await self._extract_signature_bytes(sign_result.result)
            
            # Enhanced salt generation with multiple sources (deterministic for key derivation)
            salt_material = f"{self.key_name}:{self.challenge}:{os.getenv('COMPUTERNAME', '')}"
            salt = hashlib.sha256(salt_material.encode()).digest()[:16]
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            derived_key = kdf.derive(signature)
            
            # Record successful authentication
            rate_limiter.record_attempt(auth_identifier, success=True)
            audit_log(SECURITY_EVENTS['AUTH_SUCCESS'], {
                'key_name': self.key_name,
                'timestamp': str(int(time.time()))
            })
            
            logger.info("Successfully derived encryption key")
            return derived_key
            
        except (WindowsHelloError, RateLimitError):
            raise
        except Exception as e:
            rate_limiter.record_attempt(auth_identifier, success=False)
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'key_name': self.key_name,
                'error': str(e)[:100]  # Truncate to prevent log injection
            })
            logger.error(f"Failed to derive key: {sanitize_error_message(e, 'key derivation')}")
            raise WindowsHelloError(f"Failed to derive key: {sanitize_error_message(e, 'key derivation')}")
    
    def encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-CBC with proper PKCS7 padding and integrity protection."""
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")
        
        if len(data) == 0:
            raise ValueError("Cannot encrypt empty data")
            
        logger.debug(f"Encrypting {len(data)} bytes of data")
        
        # Generate cryptographically secure random IV
        iv = secrets.token_bytes(AES_BLOCK_SIZE)
        
        # Calculate HMAC for integrity protection using proper HMAC
        hmac_key = hashlib.sha256(key + b"hmac_key_derivation").digest()
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        data_hmac = h.finalize()
        
        # Combine HMAC with data (HMAC first for security)
        data_with_hmac = data_hmac + data
        
        # Pad data using PKCS7
        padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
        padded_data = padder.update(data_with_hmac) + padder.finalize()
        
        # Encrypt using AES-256-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        result = iv + ciphertext
        logger.debug(f"Encryption completed, output size: {len(result)} bytes")
        return result
    
    def decrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-CBC with integrity verification."""
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")
        
        if len(data) < AES_BLOCK_SIZE + 32:  # IV + minimum HMAC + data
            raise ValueError("Invalid encrypted data: too short")
        
        logger.debug(f"Decrypting {len(data)} bytes of data")
        
        # Extract IV and ciphertext
        iv = data[:AES_BLOCK_SIZE]
        ciphertext = data[AES_BLOCK_SIZE:]
        
        # Decrypt using AES-256-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'error': 'decryption_failed',
                'details': 'cipher_decryption_error'
            })
            raise ValueError(f"Decryption failed: {sanitize_error_message(e, 'decryption')}")
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
        try:
            data_with_hmac = unpadder.update(padded_plaintext) + unpadder.finalize()
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'error': 'padding_removal_failed'
            })
            raise ValueError("Invalid padding - data may be corrupted")
        
        # Verify HMAC integrity (HMAC is first 32 bytes)
        if len(data_with_hmac) < 32:
            raise ValueError("Invalid decrypted data: missing HMAC")
            
        stored_hmac = data_with_hmac[:32]
        plaintext = data_with_hmac[32:]
        
        # Calculate expected HMAC using proper HMAC
        hmac_key = hashlib.sha256(key + b"hmac_key_derivation").digest()
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(plaintext)
        expected_hmac = h.finalize()
        
        # Constant-time comparison to prevent timing attacks
        if not constant_time_compare(stored_hmac, expected_hmac):
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'error': 'integrity_check_failed'
            })
            raise ValueError("Data integrity check failed - file may be corrupted or tampered with")
        
        logger.debug(f"Decryption completed, output size: {len(plaintext)} bytes")
        return plaintext
    
    @staticmethod
    def secure_clear(data: bytearray) -> None:
        """Securely clear sensitive data from memory (deprecated - use security_utils.secure_memory_clear)."""
        secure_memory_clear(data)
    
    async def encrypt_file(self, input_path: str, output_path: str) -> None:
        """Encrypt a file using Windows Hello authentication with security validation."""
        # Validate inputs
        input_file = validate_file_path(input_path, "read")
        output_file = validate_file_path(output_path, "write")
        
        if not await self.is_supported():
            raise WindowsHelloError("Windows Hello is not supported on this device")
        
        logger.info(f"Starting file encryption: {input_file.name}")
        audit_log(SECURITY_EVENTS['FILE_ENCRYPT'], {
            'input_file': input_file.name,
            'output_file': output_file.name
        })
        
        await self.ensure_key_exists()
        key = await self.derive_key_from_signature()
        key_array = bytearray(key)
        
        try:
            # Read input file with size validation
            if not input_file.exists():
                raise FileNotFoundError(f"Input file not found: {input_file}")
                
            with open(input_file, "rb") as f:
                plaintext = f.read()
            
            if len(plaintext) == 0:
                raise ValueError("Cannot encrypt empty file")
            
            # Encrypt data
            ciphertext = self.encrypt_data(plaintext, key)
            
            # Write output file atomically
            temp_output = output_file.with_suffix('.tmp')
            with open(temp_output, "wb") as f:
                f.write(ciphertext)
            
            # Atomic rename
            temp_output.replace(output_file)
            
            logger.info(f"File encryption completed: {output_file.name}")
                
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'file_encryption',
                'error': str(e)[:100]
            })
            # Clean up temporary file if it exists
            temp_output = Path(str(output_path) + '.tmp')
            if temp_output.exists():
                temp_output.unlink()
            raise
        finally:
            secure_memory_clear(key_array)
    
    async def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypt a file using Windows Hello authentication with security validation."""
        # Validate inputs
        input_file = validate_file_path(input_path, "read")
        output_file = validate_file_path(output_path, "write")
        
        if not await self.is_supported():
            raise WindowsHelloError("Windows Hello is not supported on this device")
        
        logger.info(f"Starting file decryption: {input_file.name}")
        audit_log(SECURITY_EVENTS['FILE_DECRYPT'], {
            'input_file': input_file.name,
            'output_file': output_file.name
        })
        
        await self.ensure_key_exists()
        key = await self.derive_key_from_signature()
        key_array = bytearray(key)
        
        try:
            # Read input file with validation
            if not input_file.exists():
                raise FileNotFoundError(f"Input file not found: {input_file}")
                
            with open(input_file, "rb") as f:
                ciphertext = f.read()
            
            if len(ciphertext) == 0:
                raise ValueError("Cannot decrypt empty file")
            
            # Decrypt data
            plaintext = self.decrypt_data(ciphertext, key)
            
            # Write output file atomically
            temp_output = output_file.with_suffix('.tmp')
            with open(temp_output, "wb") as f:
                f.write(plaintext)
            
            # Atomic rename
            temp_output.replace(output_file)
            
            logger.info(f"File decryption completed: {output_file.name}")
                
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'file_decryption',
                'error': str(e)[:100]
            })
            # Clean up temporary file if it exists
            temp_output = Path(str(output_path) + '.tmp')
            if temp_output.exists():
                temp_output.unlink()
            raise
        finally:
            secure_memory_clear(key_array)

async def main(mode: str, input_file: str, output_file: str) -> None:
    """Main function to handle file encryption/decryption."""
    encryptor = FileEncryptor()
    
    try:
        if mode == "encrypt":
            await encryptor.encrypt_file(input_file, output_file)
            print("File encrypted successfully.")
        elif mode == "decrypt":
            await encryptor.decrypt_file(input_file, output_file)
            print("File decrypted successfully.")
        else:
            print("Invalid mode. Use 'encrypt' or 'decrypt'.")
            
    except WindowsHelloError as e:
        print(f"Windows Hello Error: {e}")
    except FileNotFoundError as e:
        print(f"File Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Encrypt/decrypt files with Windows Hello biometric authentication.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hello_crypto.py encrypt document.txt encrypted.bin
  python hello_crypto.py decrypt encrypted.bin decrypted.txt
        """
    )
    parser.add_argument(
        "mode", 
        choices=["encrypt", "decrypt"], 
        help="Operation mode: encrypt or decrypt"
    )
    parser.add_argument("input_file", help="Path to input file")
    parser.add_argument("output_file", help="Path to output file")
    
    args = parser.parse_args()
    
    asyncio.run(main(args.mode, args.input_file, args.output_file))