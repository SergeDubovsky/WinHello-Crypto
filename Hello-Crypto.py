import argparse
import asyncio
import hashlib
import os
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from winrt.windows.security.credentials import (
    KeyCredentialManager, 
    KeyCredentialCreationOption,
    KeyCredentialStatus
)
from winrt.windows.storage.streams import DataWriter, DataReader

# Constants
KEY_NAME = "FileEncryptKey"
CHALLENGE_MESSAGE = "FixedChallengeForKeyDerivation"
AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32  # 256 bits

class WindowsHelloError(Exception):
    """Custom exception for Windows Hello operations."""
    pass


class FileEncryptor:
    """Windows Hello-based file encryption and decryption."""
    
    def __init__(self, key_name: str = KEY_NAME, challenge: str = CHALLENGE_MESSAGE):
        self.key_name = key_name
        self.challenge = challenge
    
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
        """Derive encryption key from Windows Hello signature."""
        try:
            # Open the key
            open_result = await KeyCredentialManager.open_async(self.key_name)
            if open_result.status != KeyCredentialStatus.SUCCESS:
                raise WindowsHelloError("Failed to open Windows Hello key")

            # Prepare challenge buffer
            writer = DataWriter()
            writer.write_string(self.challenge)
            challenge_buffer = writer.detach_buffer()

            # Sign with biometric authentication
            sign_result = await open_result.credential.request_sign_async(challenge_buffer)
            if sign_result.status != KeyCredentialStatus.SUCCESS:
                raise WindowsHelloError("Biometric authentication failed or was cancelled")

            # Extract signature and derive key
            signature = await self._extract_signature_bytes(sign_result.result)
            return hashlib.sha256(signature).digest()
            
        except WindowsHelloError:
            raise
        except Exception as e:
            raise WindowsHelloError(f"Failed to derive key: {e}")
    
    def encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-CBC with proper PKCS7 padding."""
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")
        
        # Generate random IV
        iv = secrets.token_bytes(AES_BLOCK_SIZE)
        
        # Pad data using PKCS7
        padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + ciphertext
    
    def decrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-CBC and remove PKCS7 padding."""
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")
        
        if len(data) < AES_BLOCK_SIZE:
            raise ValueError("Invalid encrypted data: too short")
        
        # Extract IV and ciphertext
        iv = data[:AES_BLOCK_SIZE]
        ciphertext = data[AES_BLOCK_SIZE:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    @staticmethod
    def secure_clear(data: bytearray) -> None:
        """Securely clear sensitive data from memory."""
        if data:
            for i in range(len(data)):
                data[i] = 0
    
    async def encrypt_file(self, input_path: str, output_path: str) -> None:
        """Encrypt a file using Windows Hello authentication."""
        if not await self.is_supported():
            raise WindowsHelloError("Windows Hello is not supported on this device")
        
        await self.ensure_key_exists()
        key = await self.derive_key_from_signature()
        key_array = bytearray(key)
        
        try:
            with open(input_path, "rb") as f:
                plaintext = f.read()
            
            ciphertext = self.encrypt_data(plaintext, key)
            
            with open(output_path, "wb") as f:
                f.write(ciphertext)
                
        finally:
            self.secure_clear(key_array)
    
    async def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypt a file using Windows Hello authentication."""
        if not await self.is_supported():
            raise WindowsHelloError("Windows Hello is not supported on this device")
        
        await self.ensure_key_exists()
        key = await self.derive_key_from_signature()
        key_array = bytearray(key)
        
        try:
            with open(input_path, "rb") as f:
                ciphertext = f.read()
            
            plaintext = self.decrypt_data(ciphertext, key)
            
            with open(output_path, "wb") as f:
                f.write(plaintext)
                
        finally:
            self.secure_clear(key_array)

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
  python Hello-Crypto.py encrypt document.txt encrypted.bin
  python Hello-Crypto.py decrypt encrypted.bin decrypted.txt
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