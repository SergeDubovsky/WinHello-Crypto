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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag
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

# Windows API imports for window management
try:
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    WINDOWS_API_AVAILABLE = True
except ImportError:
    WINDOWS_API_AVAILABLE = False

# Import security utilities
from security_utils import (
    SecurityError, ValidationError, RateLimitError, rate_limiter,
    audit_log, validate_file_path, secure_memory_clear,
    sanitize_error_message
)
from security_config import (
    AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE, AES_KEY_SIZE,
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
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


def _bring_window_to_foreground():
    """Bring the current console window to the foreground before Windows Hello prompt."""
    if not WINDOWS_API_AVAILABLE or os.name != 'nt':
        return
    
    try:
        # Get the console window handle
        console_window = kernel32.GetConsoleWindow()
        if console_window:
            # Get the current foreground window
            current_foreground = user32.GetForegroundWindow()
            
            # Force the console window to the foreground with multiple approaches
            user32.ShowWindow(console_window, 9)  # SW_RESTORE - restore if minimized
            user32.SetWindowPos(console_window, -1, 0, 0, 0, 0, 0x0003)  # HWND_TOPMOST, SWP_NOMOVE | SWP_NOSIZE
            user32.SetWindowPos(console_window, -2, 0, 0, 0, 0, 0x0003)  # HWND_NOTOPMOST, SWP_NOMOVE | SWP_NOSIZE
            
            # Use a more aggressive approach to set foreground
            if current_foreground != console_window:
                # Attach to the current foreground window's thread
                current_thread = kernel32.GetCurrentThreadId()
                if current_foreground:
                    foreground_thread = user32.GetWindowThreadProcessId(current_foreground, None)
                    if foreground_thread != current_thread:
                        user32.AttachThreadInput(foreground_thread, current_thread, True)
                        user32.SetForegroundWindow(console_window)
                        user32.SetFocus(console_window)
                        user32.AttachThreadInput(foreground_thread, current_thread, False)
                    else:
                        user32.SetForegroundWindow(console_window)
                        user32.SetFocus(console_window)
                else:
                    user32.SetForegroundWindow(console_window)
                    user32.SetFocus(console_window)
            
            user32.BringWindowToTop(console_window)
            
            # Small delay to ensure window operations complete
            time.sleep(0.2)
            logger.info("Brought console window to foreground with focus for Windows Hello prompt")
    except Exception as e:
        # Don't fail the authentication if window management fails
        logger.warning(f"Failed to bring window to foreground: {e}")


def _find_and_focus_hello_dialog():
    """Find and focus the Windows Hello authentication dialog."""
    if not WINDOWS_API_AVAILABLE or os.name != 'nt':
        return False
        
    try:
        # Target the specific Windows Hello dialog
        hello_found = False
        
        def enum_windows_proc(hwnd, lparam):
            """Callback function for EnumWindows."""
            nonlocal hello_found
            try:
                # Get window title and class name
                title_length = user32.GetWindowTextLengthW(hwnd)
                title = ""
                if title_length > 0:
                    title_buffer = ctypes.create_unicode_buffer(title_length + 1)
                    user32.GetWindowTextW(hwnd, title_buffer, title_length + 1)
                    title = title_buffer.value
                    
                # Get class name
                class_buffer = ctypes.create_unicode_buffer(256)
                user32.GetClassNameW(hwnd, class_buffer, 256)
                class_name = class_buffer.value
                
                # Look specifically for Windows Hello/Security dialogs
                if (("Windows Security" in title or "Windows Hello" in title) and 
                    ("Credential Dialog" in class_name or "SystemSettings" in class_name)):
                    
                    # Check if window is visible
                    if user32.IsWindowVisible(hwnd):
                        if not hello_found:  # Only log the first time we find it
                            logger.info(f"Focusing Windows Hello dialog: '{title}'")
                        
                        # More aggressive window activation
                        # Step 1: Restore and show the window
                        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                        user32.ShowWindow(hwnd, 3)  # SW_MAXIMIZE then SW_RESTORE to force activation
                        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                        
                        # Step 2: Set as topmost temporarily
                        user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x0003)  # HWND_TOPMOST
                        
                        # Step 3: Bring to foreground
                        user32.SetForegroundWindow(hwnd)
                        user32.BringWindowToTop(hwnd)
                        
                        # Step 4: Set focus and activate
                        user32.SetActiveWindow(hwnd)
                        user32.SetFocus(hwnd)
                        
                        # Step 5: Remove topmost status
                        user32.SetWindowPos(hwnd, -2, 0, 0, 0, 0, 0x0003)  # HWND_NOTOPMOST
                        
                        # Step 6: Try to send an activation message
                        user32.SendMessageW(hwnd, 0x0006, 1, 0)  # WM_ACTIVATE with WA_ACTIVE
                        
                        # Step 7: Flash the window to draw attention
                        user32.FlashWindow(hwnd, True)
                        
                        # Step 8: Try to simulate a click to activate biometric sensor
                        # Get the window rectangle
                        rect = ctypes.wintypes.RECT()
                        if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                            # Calculate center of the window
                            center_x = (rect.left + rect.right) // 2
                            center_y = (rect.top + rect.bottom) // 2
                            
                            # Simulate a mouse click at the center of the dialog
                            user32.SetCursorPos(center_x, center_y)
                            user32.mouse_event(0x0002, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
                            user32.mouse_event(0x0004, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
                        
                        hello_found = True
                        return False  # Stop enumeration
                        
            except Exception as e:
                # Continue enumeration even if we fail on one window
                pass
            return True  # Continue enumeration
        
        # Define the callback type
        EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        callback = EnumWindowsProc(enum_windows_proc)
        
        # Enumerate all windows
        user32.EnumWindows(callback, 0)
        return hello_found
        
    except Exception as e:
        logger.warning(f"Failed to find Windows Hello dialog: {e}")
        return False


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
            
            # Bring console window to foreground to ensure Windows Hello prompt is visible
            _bring_window_to_foreground()
            
            # Inform user about the authentication request
            print("[Windows Hello] Authentication required - please complete biometric verification...", file=sys.stderr)
            print("[Tip] If the dialog appears but doesn't respond, it should now be automatically activated.", file=sys.stderr)
            
            # Create a task to find and focus the Windows Hello dialog
            async def focus_hello_dialog():
                # Try to find the dialog multiple times
                for i in range(15):  # Try for up to 3 seconds
                    await asyncio.sleep(0.2)
                    if _find_and_focus_hello_dialog():
                        # Found and focused the dialog, give it a moment to fully activate
                        await asyncio.sleep(0.3)
                        break
            
            # Start the focus task
            focus_task = asyncio.create_task(focus_hello_dialog())
            
            try:
                # Start the authentication request
                sign_result = await open_result.credential.request_sign_async(challenge_buffer)
            finally:
                # Cancel the focus task
                focus_task.cancel()
                try:
                    await focus_task
                except asyncio.CancelledError:
                    pass
            
            if sign_result.status != KeyCredentialStatus.SUCCESS:
                rate_limiter.record_attempt(auth_identifier, success=False)
                audit_log(SECURITY_EVENTS['AUTH_FAILURE'], {
                    'key_name': self.key_name,
                    'error': 'biometric_auth_failed'
                })
                raise WindowsHelloError("Biometric authentication failed or was cancelled")

            # Extract signature and derive key with Argon2id
            signature = await self._extract_signature_bytes(sign_result.result)

            # Enhanced salt generation with multiple sources (deterministic for key derivation)
            salt_material = f"{self.key_name}:{self.challenge}:{os.getenv('COMPUTERNAME', '')}"
            salt = hashlib.sha256(salt_material.encode()).digest()[:16]

            kdf = Argon2id(
                salt=salt,
                length=AES_KEY_SIZE,
                iterations=ARGON2_TIME_COST,
                lanes=ARGON2_PARALLELISM,
                memory_cost=ARGON2_MEMORY_COST,
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
        """Encrypt data using AES-256-GCM providing confidentiality and integrity."""
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")

        if len(data) == 0:
            raise ValueError("Cannot encrypt empty data")

        # Generate cryptographically secure random nonce
        nonce = secrets.token_bytes(AES_GCM_NONCE_SIZE)

        aead = AESGCM(key)
        ciphertext = aead.encrypt(nonce, data, None)  # ciphertext includes authentication tag

        # Return nonce + ciphertext (which already includes tag)
        return nonce + ciphertext
    
    def decrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM with integrity verification."""
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes")

        if len(data) < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
            raise ValueError("Invalid encrypted data: too short")

        # Extract nonce and ciphertext (which includes the tag)
        nonce = data[:AES_GCM_NONCE_SIZE]
        ciphertext = data[AES_GCM_NONCE_SIZE:]

        aead = AESGCM(key)
        try:
            plaintext = aead.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'error': 'integrity_check_failed'
            })
            raise ValueError("Data integrity check failed - file may be corrupted or tampered with")
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'error': 'decryption_failed',
                'details': 'cipher_decryption_error'
            })
            raise ValueError(f"Decryption failed: {sanitize_error_message(e, 'decryption')}")

        logger.debug(f"Decryption completed, output size: {len(plaintext)} bytes")
        return plaintext
    
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

        temp_output = output_file.with_suffix('.tmp')

        try:
            # Read input file with size validation
            if not input_file.exists():
                raise FileNotFoundError(f"Input file not found: {input_file}")

            plaintext = await asyncio.to_thread(input_file.read_bytes)

            if len(plaintext) == 0:
                raise ValueError("Cannot encrypt empty file")

            # Encrypt data
            ciphertext = self.encrypt_data(plaintext, key)

            # Write output file atomically
            await asyncio.to_thread(temp_output.write_bytes, ciphertext)

            # Atomic rename
            temp_output.replace(output_file)

            logger.info(f"File encryption completed: {output_file.name}")

        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'file_encryption',
                'error': str(e)[:100]
            })
            # Clean up temporary file if it exists
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

        temp_output = output_file.with_suffix('.tmp')

        try:
            # Read input file with validation
            if not input_file.exists():
                raise FileNotFoundError(f"Input file not found: {input_file}")

            ciphertext = await asyncio.to_thread(input_file.read_bytes)

            if len(ciphertext) == 0:
                raise ValueError("Cannot decrypt empty file")

            # Decrypt data
            plaintext = self.decrypt_data(ciphertext, key)

            # Write output file atomically
            await asyncio.to_thread(temp_output.write_bytes, plaintext)

            # Atomic rename
            temp_output.replace(output_file)

            logger.info(f"File decryption completed: {output_file.name}")

        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'file_decryption',
                'error': str(e)[:100]
            })
            # Clean up temporary file if it exists
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


def cli_main():
    """CLI entry point for console script."""
    parser = argparse.ArgumentParser(
        description="Encrypt/decrypt files with Windows Hello biometric authentication.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  winhello-crypto encrypt document.txt encrypted.bin
  winhello-crypto decrypt encrypted.bin decrypted.txt
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


if __name__ == "__main__":
    cli_main()
