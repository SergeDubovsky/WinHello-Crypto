#!/usr/bin/env python3
"""
AWS Credentials Manager with Windows Hello Encryption
A secure credential manager that uses Windows Hello biometric authentication
to encrypt and decrypt AWS credentials stored locally.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
import configparser
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Union, List, Tuple

from hello_crypto import FileEncryptor, WindowsHelloError
from security_utils import (
    SecurityError, ValidationError, RateLimitError, rate_limiter,
    audit_log, validate_aws_credentials, validate_aws_region,
    validate_profile_name, secure_memory_clear, sanitize_error_message
)
from security_config import (
    AWS_PATTERNS, AWS_REGIONS, SECURITY_EVENTS, KEY_NAME_AWS, AWS_CHALLENGE_MESSAGE
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)


class AWSCredentialManager:
    """Manages AWS credentials with Windows Hello encryption."""
    
    # Validation patterns imported from security_config
    
    def __init__(self):
        self.encryptor = FileEncryptor(
            key_name=KEY_NAME_AWS,
            challenge=AWS_CHALLENGE_MESSAGE
        )
        self.aws_dir = Path.home() / ".aws"
        self.credentials_dir = self.aws_dir / "hello-encrypted"
        
    def _validate_profile_name(self, profile_name: str) -> None:
        """Validate AWS profile name format."""
        validate_profile_name(profile_name)
    
    def _validate_aws_credentials(self, access_key: str, secret_key: str, 
                                 session_token: Optional[str] = None) -> None:
        """Validate AWS credential format."""
        validate_aws_credentials(access_key, secret_key, session_token)
        
    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        self.aws_dir.mkdir(exist_ok=True)
        self.credentials_dir.mkdir(exist_ok=True)
        
    def _get_credential_file_path(self, profile_name: str) -> Path:
        """Get the path to the encrypted credential file for a profile."""
        return self.credentials_dir / f"{profile_name}.enc"
    
    async def add_profile(self, profile_name: str, access_key: str, 
                         secret_key: str, session_token: Optional[str] = None,
                         region: Optional[str] = None) -> None:
        """Add or update AWS credentials for a profile."""
        try:
            # Validate inputs
            self._validate_profile_name(profile_name)
            self._validate_aws_credentials(access_key, secret_key, session_token)
            
            if region:
                validate_aws_region(region)
                
            # Audit log the attempt
            audit_log(SECURITY_EVENTS['CRED_STORE'], {
                'profile_name': profile_name,
                'has_session_token': bool(session_token),
                'region': region
            })
            
            if not await self.encryptor.is_supported():
                raise WindowsHelloError("Windows Hello is not supported on this device")
            
            logger.info(f"Adding profile '{profile_name}' with Windows Hello encryption")
            
            # Prepare credential data
            credential_data = {
                "aws_access_key_id": access_key,
                "aws_secret_access_key": secret_key,
                # Use wall clock time for creation timestamp
                "created_at": time.time(),
                "profile_name": profile_name
            }
            
            if session_token:
                credential_data["aws_session_token"] = session_token
                
            if region:
                credential_data["region"] = region
                
            # Convert to JSON bytes
            json_data = json.dumps(credential_data, indent=2).encode('utf-8')
            
            # Ensure directories exist
            self._ensure_directories()
            
            # Encrypt and store
            credential_file = self._get_credential_file_path(profile_name)
            await self.encryptor.ensure_key_exists()
            
            # Derive key and encrypt
            key = await self.encryptor.derive_key_from_signature()
            encrypted_data = self.encryptor.encrypt_data(json_data, key)
            
            # Securely clear the key from memory
            key_array = bytearray(key)
            try:
                # Write encrypted data atomically
                temp_file = credential_file.with_suffix('.tmp')
                with open(temp_file, "wb") as f:
                    f.write(encrypted_data)
                temp_file.replace(credential_file)
                
                logger.info(f"Credentials for profile '{profile_name}' encrypted and stored")
                print(f"✅ Credentials for profile '{profile_name}' encrypted and stored successfully.")
                
                # Update AWS config file
                await self._update_aws_config(profile_name, region)
                
                # Audit successful storage
                audit_log(SECURITY_EVENTS['CRED_STORE'], {
                    'profile_name': profile_name,
                    'success': True
                })
                
            finally:
                secure_memory_clear(key_array)
                
        except (ValueError, ValidationError) as e:
            audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
                'operation': 'add_profile',
                'profile_name': profile_name,
                'error': str(e)[:100]
            })
            logger.error(f"Validation error: {e}")
            raise
        except WindowsHelloError as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'add_profile', 
                'profile_name': profile_name,
                'error': str(e)[:100]
            })
            logger.error(f"Windows Hello error: {e}")
            raise
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'add_profile',
                'profile_name': profile_name,
                'error': str(e)[:100]
            })
            logger.error(f"Unexpected error adding profile '{profile_name}': {sanitize_error_message(e, 'credential storage')}")
            raise WindowsHelloError(f"Failed to add profile: {sanitize_error_message(e, 'credential storage')}")
        
    async def _update_aws_config(self, profile_name: str, region: Optional[str] = None) -> None:
        """Update the AWS config file with credential_process."""
        try:
            config_file = self.aws_dir / "config"

            config_text = ""
            if config_file.exists():
                try:
                    config_text = config_file.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    logger.warning("AWS config file has encoding issues, treating as empty")
                    config_text = ""

            parser = configparser.RawConfigParser()
            parser.optionxform = str
            if config_text:
                try:
                    parser.read_string(config_text)
                except configparser.Error:
                    logger.warning("AWS config file is malformed, starting with empty config")

            section_name = f"profile {profile_name}"
            if not parser.has_section(section_name):
                parser.add_section(section_name)

            try:
                import shutil
                if shutil.which("aws-hello-creds"):
                    cp_cmd = f"aws-hello-creds get-credentials --profile {profile_name}"
                else:
                    script_path = Path(__file__).absolute()
                    cp_cmd = f"python \"{script_path}\" get-credentials --profile {profile_name}"
            except Exception:
                script_path = Path(__file__).absolute()
                cp_cmd = f"python \"{script_path}\" get-credentials --profile {profile_name}"

            parser.set(section_name, "credential_process", cp_cmd)
            if region:
                parser.set(section_name, "region", region)
            else:
                if parser.has_option(section_name, "region"):
                    parser.remove_option(section_name, "region")
            parser.set(section_name, "output", "json")

            lines = config_text.splitlines()
            section_header = f"[profile {profile_name}]"
            start = end = None
            for idx, line in enumerate(lines):
                if line.strip() == section_header:
                    start = idx
                    end = idx + 1
                    while end < len(lines) and not (
                        lines[end].strip().startswith("[") and lines[end].strip().endswith("]")
                    ):
                        end += 1
                    break

            items = parser.items(section_name)

            if start is not None:
                preserved = [
                    l for l in lines[start + 1 : end]
                    if l.strip().startswith("#") or l.strip().startswith(";") or l.strip() == ""
                ]
                new_section = [section_header]
                new_section.extend(preserved)
                for key, value in items:
                    new_section.append(f"{key} = {value}")
                lines = lines[:start] + new_section + lines[end:]
            else:
                if lines and lines[-1].strip():
                    lines.append("")
                new_section = [section_header]
                for key, value in items:
                    new_section.append(f"{key} = {value}")
                lines.extend(new_section)

            temp_config = config_file.with_suffix(".tmp")
            temp_config.write_text("\n".join(lines) + "\n", encoding="utf-8")
            temp_config.replace(config_file)

            logger.info(f"AWS config updated for profile '{profile_name}'")
            print(f"✅ AWS config updated for profile '{profile_name}'.")

        except Exception as e:
            logger.error(f"Failed to update AWS config: {e}")
            raise WindowsHelloError(f"Failed to update AWS config: {e}")
        
    async def get_credentials(self, profile_name: str) -> Dict[str, Union[str, float]]:
        """Retrieve and decrypt credentials for a profile."""
        try:
            self._validate_profile_name(profile_name)
            
            if not await self.encryptor.is_supported():
                raise WindowsHelloError("Windows Hello is not supported on this device")
                
            credential_file = self._get_credential_file_path(profile_name)
            
            if not credential_file.exists():
                raise FileNotFoundError(f"No encrypted credentials found for profile '{profile_name}'")
                
            logger.info(f"Retrieving credentials for profile '{profile_name}'")
            audit_log(SECURITY_EVENTS['CRED_RETRIEVE'], {
                'profile_name': profile_name
            })
            
            # Read encrypted data
            try:
                with open(credential_file, "rb") as f:
                    encrypted_data = f.read()
            except IOError as e:
                raise WindowsHelloError(f"Failed to read credential file: {e}")
                
            # Decrypt
            key = await self.encryptor.derive_key_from_signature()
            key_array = bytearray(key)
            
            try:
                decrypted_data = self.encryptor.decrypt_data(encrypted_data, key)
                
                # Parse JSON
                try:
                    credential_data = json.loads(decrypted_data.decode('utf-8'))
                except json.JSONDecodeError as e:
                    audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                        'operation': 'credential_parsing',
                        'profile_name': profile_name,
                        'error': 'json_decode_error'
                    })
                    raise WindowsHelloError(f"Invalid credential data format: {e}")
                
                # Validate required fields
                required_fields = ["aws_access_key_id", "aws_secret_access_key"]
                missing_fields = [field for field in required_fields if field not in credential_data]
                if missing_fields:
                    audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
                        'operation': 'credential_validation',
                        'profile_name': profile_name,
                        'missing_fields': missing_fields
                    })
                    raise WindowsHelloError(f"Missing required credential fields: {', '.join(missing_fields)}")
                
                # Audit successful retrieval
                audit_log(SECURITY_EVENTS['CRED_RETRIEVE'], {
                    'profile_name': profile_name,
                    'success': True,
                    'has_session_token': 'aws_session_token' in credential_data
                })
                
                logger.info(f"Successfully retrieved credentials for profile '{profile_name}'")
                return credential_data
                
            finally:
                secure_memory_clear(key_array)
                
        except WindowsHelloError:
            raise
        except (ValueError, ValidationError) as e:
            audit_log(SECURITY_EVENTS['VALIDATION_ERROR'], {
                'operation': 'get_credentials',
                'profile_name': profile_name,
                'error': str(e)[:100]
            })
            logger.error(f"Validation error: {e}")
            raise
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'get_credentials',
                'profile_name': profile_name,
                'error': str(e)[:100]
            })
            logger.error(f"Unexpected error retrieving credentials for '{profile_name}': {sanitize_error_message(e, 'credential retrieval')}")
            raise WindowsHelloError(f"Failed to retrieve credentials: {sanitize_error_message(e, 'credential retrieval')}")
        
    async def list_profiles(self) -> None:
        """List all available encrypted profiles."""
        if not self.credentials_dir.exists():
            print("No encrypted profiles found.")
            return
            
        profiles = []
        for file_path in self.credentials_dir.glob("*.enc"):
            profile_name = file_path.stem
            profiles.append(profile_name)
            
        if profiles:
            print("Available encrypted profiles:")
            for profile in sorted(profiles):
                print(f"  • {profile}")
        else:
            print("No encrypted profiles found.")
            
    async def remove_profile(self, profile_name: str) -> None:
        """Remove encrypted credentials for a profile."""
        credential_file = self._get_credential_file_path(profile_name)
        
        if not credential_file.exists():
            print(f"No encrypted credentials found for profile '{profile_name}'")
            return
            
        credential_file.unlink()
        
        # Audit the removal
        audit_log(SECURITY_EVENTS['CRED_RETRIEVE'], {
            'operation': 'remove_profile',
            'profile_name': profile_name,
            'success': True
        })
        
        print(f"✅ Encrypted credentials for profile '{profile_name}' removed.")
        print(f"Note: You may want to manually remove the profile from ~/.aws/config")

    async def _backup_credentials(self, profile_name: str, credentials: Dict[str, Union[str, float]]) -> None:
        """Create a backup of current credentials before rotation."""
        backup_dir = self.credentials_dir / "backups"
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"{profile_name}_{timestamp}.enc"
        
        # Add backup metadata
        backup_data = {
            **credentials,
            "backup_created_at": time.time(),
            "backup_reason": "credential_rotation",
            "original_profile": profile_name
        }
        
        json_data = json.dumps(backup_data, indent=2).encode('utf-8')
        
        # Encrypt and store backup
        key = await self.encryptor.derive_key_from_signature()
        encrypted_data = self.encryptor.encrypt_data(json_data, key)
        key_array = bytearray(key)
        
        try:
            with open(backup_file, "wb") as f:
                f.write(encrypted_data)
            logger.info(f"Backup created for profile '{profile_name}' at {backup_file}")
        finally:
            secure_memory_clear(key_array)

    async def _check_credential_age(self, profile_name: str) -> Tuple[bool, Optional[float], Optional[str]]:
        """Check if credentials are approaching expiration or are old."""
        try:
            credentials = await self.get_credentials(profile_name)
            created_at = credentials.get('created_at', 0)
            session_token = credentials.get('aws_session_token')
            
            if session_token:
                # Session tokens typically expire in 1-12 hours
                # Check if they're older than 30 minutes for warning
                age_hours = (time.time() - created_at) / 3600
                if age_hours > 0.5:  # 30 minutes
                    return True, age_hours, "session_token_aging"
            else:
                # Long-term credentials - warn if older than 90 days
                age_days = (time.time() - created_at) / 86400
                if age_days > 90:
                    return True, age_days, "long_term_aging"
                    
            return False, None, None
            
        except Exception as e:
            logger.warning(f"Could not check credential age for '{profile_name}': {e}")
            return False, None, None

    async def check_rotation_needed(self, profile_name: str) -> None:
        """Check if credentials need rotation and provide recommendations."""
        try:
            self._validate_profile_name(profile_name)
            
            needs_rotation, age, reason = await self._check_credential_age(profile_name)
            
            print(f"🔍 Checking rotation status for profile '{profile_name}'...")
            
            if not needs_rotation:
                print(f"✅ Credentials are fresh - no rotation needed")
                return
                
            if reason == "session_token_aging":
                print(f"⚠️  Session token is {age:.1f} hours old")
                print(f"💡 Consider rotating temporary credentials if they're not working")
                print(f"   Use: python aws_hello_creds.py rotate-credentials {profile_name} --type temporary")
            elif reason == "long_term_aging":
                print(f"⚠️  Long-term credentials are {age:.0f} days old")
                print(f"💡 Consider rotating for security best practices")
                print(f"   Use: python aws_hello_creds.py rotate-credentials {profile_name} --type access-key")
                
            # Audit the check
            audit_log(SECURITY_EVENTS['CRED_RETRIEVE'], {
                'operation': 'rotation_check',
                'profile_name': profile_name,
                'needs_rotation': needs_rotation,
                'age': age,
                'reason': reason
            })
            
        except Exception as e:
            print(f"❌ Error checking rotation status: {sanitize_error_message(e, 'rotation check')}")
            raise

    async def rotate_credentials(self, profile_name: str, rotation_type: str = "auto", 
                               new_access_key: Optional[str] = None, 
                               new_secret_key: Optional[str] = None,
                               new_session_token: Optional[str] = None) -> None:
        """Rotate AWS credentials with backup of old credentials."""
        try:
            self._validate_profile_name(profile_name)
            
            print(f"🔄 Starting credential rotation for profile '{profile_name}'...")
            
            # Get current credentials for backup
            try:
                current_creds = await self.get_credentials(profile_name)
                print(f"📦 Creating backup of current credentials...")
                await self._backup_credentials(profile_name, current_creds)
            except Exception as e:
                print(f"⚠️  Could not backup current credentials: {e}")
                response = input("Continue rotation without backup? (y/N): ")
                if response.lower() != 'y':
                    print("❌ Rotation cancelled")
                    return
            
            # Determine rotation type
            if rotation_type == "auto":
                has_session = current_creds.get('aws_session_token') is not None
                rotation_type = "temporary" if has_session else "access-key"
                print(f"🤖 Auto-detected rotation type: {rotation_type}")
            
            if rotation_type == "manual":
                if not all([new_access_key, new_secret_key]):
                    raise ValueError("Manual rotation requires --access-key and --secret-key")
                
                print(f"🔧 Performing manual credential rotation...")
                
                # Validate new credentials
                self._validate_aws_credentials(new_access_key, new_secret_key, new_session_token)
                
                # Update with new credentials, preserving region
                region = current_creds.get('region')
                await self.add_profile(
                    profile_name, 
                    new_access_key, 
                    new_secret_key, 
                    new_session_token,
                    region
                )
                
            elif rotation_type == "temporary":
                print(f"💡 For temporary credential rotation, you'll need to:")
                print(f"   1. Get new temporary credentials from AWS console or CLI")
                print(f"   2. Run: python aws_hello_creds.py rotate-credentials {profile_name} --type manual \\")
                print(f"           --access-key YOUR_NEW_KEY --secret-key YOUR_NEW_SECRET --session-token YOUR_TOKEN")
                
            elif rotation_type == "access-key":
                print(f"💡 For access key rotation, you'll need to:")
                print(f"   1. Create new access keys in AWS IAM console")
                print(f"   2. Run: python aws_hello_creds.py rotate-credentials {profile_name} --type manual \\")
                print(f"           --access-key YOUR_NEW_KEY --secret-key YOUR_NEW_SECRET")
                print(f"   3. Test the new credentials")
                print(f"   4. Delete the old access keys in AWS IAM console")
                
            else:
                raise ValueError(f"Invalid rotation type: {rotation_type}")
            
            if rotation_type == "manual":
                print(f"✅ Credential rotation completed successfully!")
                print(f"💾 Old credentials backed up to backups/ directory")
                print(f"🧪 Test the new credentials with: aws sts get-caller-identity --profile {profile_name}")
            
            # Audit the rotation
            audit_log(SECURITY_EVENTS['CRED_STORE'], {
                'operation': 'credential_rotation',
                'profile_name': profile_name,
                'rotation_type': rotation_type,
                'success': True
            })
            
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'credential_rotation',
                'profile_name': profile_name,
                'error': str(e)[:100]
            })
            print(f"❌ Credential rotation failed: {sanitize_error_message(e, 'credential rotation')}")
            raise

    async def list_backups(self, profile_name: Optional[str] = None) -> None:
        """List available credential backups."""
        backup_dir = self.credentials_dir / "backups"
        
        if not backup_dir.exists():
            print("📁 No backups directory found")
            return
            
        backup_files = list(backup_dir.glob("*.enc"))
        
        if not backup_files:
            print("📁 No credential backups found")
            return
            
        print(f"📋 Available credential backups:")
        print()
        
        for backup_file in sorted(backup_files):
            # Parse filename: profile_timestamp.enc
            name_parts = backup_file.stem.split('_')
            if len(name_parts) >= 2:
                backup_profile = '_'.join(name_parts[:-2]) if len(name_parts) > 2 else name_parts[0]
                timestamp_str = '_'.join(name_parts[-2:])
                
                if profile_name and backup_profile != profile_name:
                    continue
                    
                try:
                    # Parse timestamp
                    timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                    age = datetime.now() - timestamp
                    
                    print(f"  📦 {backup_profile}")
                    print(f"     Created: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"     Age: {age.days} days, {age.seconds//3600} hours")
                    print(f"     File: {backup_file.name}")
                    print()
                except ValueError:
                    print(f"  📦 {backup_file.name} (unknown format)")
                    print()

    async def restore_from_backup(self, profile_name: str, backup_timestamp: str) -> None:
        """Restore credentials from a backup."""
        try:
            self._validate_profile_name(profile_name)
            
            backup_dir = self.credentials_dir / "backups"
            backup_file = backup_dir / f"{profile_name}_{backup_timestamp}.enc"
            
            if not backup_file.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_file}")
                
            print(f"🔄 Restoring credentials for '{profile_name}' from backup...")
            print(f"📁 Backup file: {backup_file.name}")
            
            # Read and decrypt backup
            with open(backup_file, "rb") as f:
                encrypted_data = f.read()
                
            key = await self.encryptor.derive_key_from_signature()
            key_array = bytearray(key)
            
            try:
                decrypted_data = self.encryptor.decrypt_data(encrypted_data, key)
                backup_creds = json.loads(decrypted_data.decode('utf-8'))
                
                # Extract credential components
                access_key = backup_creds.get('aws_access_key_id')
                secret_key = backup_creds.get('aws_secret_access_key')
                session_token = backup_creds.get('aws_session_token')
                region = backup_creds.get('region')
                
                if not access_key or not secret_key:
                    raise ValueError("Invalid backup file - missing required credentials")
                
                # Create current backup before restore
                try:
                    current_creds = await self.get_credentials(profile_name)
                    await self._backup_credentials(f"{profile_name}_pre_restore", current_creds)
                    print(f"📦 Current credentials backed up before restore")
                except Exception:
                    pass  # Current credentials might not exist
                
                # Restore credentials
                await self.add_profile(profile_name, access_key, secret_key, session_token, region)
                
                print(f"✅ Credentials restored successfully!")
                print(f"🧪 Test with: aws sts get-caller-identity --profile {profile_name}")
                
                # Audit the restore
                audit_log(SECURITY_EVENTS['CRED_STORE'], {
                    'operation': 'credential_restore',
                    'profile_name': profile_name,
                    'backup_file': backup_file.name,
                    'success': True
                })
                
            finally:
                secure_memory_clear(key_array)
                
        except Exception as e:
            audit_log(SECURITY_EVENTS['SECURITY_ERROR'], {
                'operation': 'credential_restore',
                'profile_name': profile_name,
                'error': str(e)[:100]
            })
            print(f"❌ Restore failed: {sanitize_error_message(e, 'credential restore')}")
            raise

    def _detect_shell(self) -> str:
        """Detect the current shell environment."""
        # Check environment variables that indicate the shell
        shell_env = os.environ.get('SHELL', '').lower()
        if 'bash' in shell_env:
            return 'bash'
        elif 'zsh' in shell_env:
            return 'zsh'
        elif 'sh' in shell_env and 'bash' not in shell_env:
            return 'sh'
        
        # Check for PowerShell specific environment variables
        if os.environ.get('PSModulePath') or os.environ.get('POWERSHELL_DISTRIBUTION_CHANNEL'):
            return 'powershell'
        
        # Check for PowerShell execution policy (PowerShell specific)
        if os.environ.get('PSExecutionPolicyPreference'):
            return 'powershell'
        
        # Check parent process name (Windows)
        try:
            import psutil
            parent = psutil.Process().parent()
            if parent:
                parent_name = parent.name().lower()
                if 'powershell' in parent_name or 'pwsh' in parent_name:
                    return 'powershell'
                elif 'cmd' in parent_name:
                    return 'cmd'
                elif 'bash' in parent_name:
                    return 'bash'
                elif 'zsh' in parent_name:
                    return 'zsh'
                elif 'windowsterminal' in parent_name or 'wt' in parent_name:
                    # Windows Terminal - check for PowerShell as default
                    return 'powershell'
        except (ImportError, Exception):
            # psutil not available or other error, continue with other detection methods
            pass
        
        # Check for Windows Command Prompt
        if os.environ.get('COMSPEC', '').lower().endswith('cmd.exe'):
            return 'cmd'
        
        # Check for WSL or Linux environment
        if os.environ.get('WSL_DISTRO_NAME') or os.path.exists('/proc/version'):
            return 'bash'
        
        # Check for Windows Terminal
        if os.environ.get('WT_SESSION'):
            return 'powershell'  # Windows Terminal typically uses PowerShell
        
        # Check VS Code integrated terminal
        if os.environ.get('TERM_PROGRAM') == 'vscode':
            # In VS Code, check for PowerShell specific vars
            if os.environ.get('PSModulePath'):
                return 'powershell'
            return 'powershell'  # Default to PowerShell in VS Code on Windows
        
        # Default based on OS
        if os.name == 'nt':  # Windows
            return 'powershell'  # Modern Windows defaults to PowerShell
        else:  # Unix-like
            return 'bash'

    async def output_env_vars(self, profile_name: str, shell_type: Optional[str] = None) -> None:
        """Output environment variable commands for setting AWS credentials."""
        try:
            credentials = await self.get_credentials(profile_name)
            
            # Auto-detect shell if not specified
            if shell_type is None:
                shell_type = self._detect_shell()
                logger.info(f"Auto-detected shell: {shell_type}")
            
            # Audit the env var access
            audit_log(SECURITY_EVENTS['CRED_RETRIEVE'], {
                'operation': 'output_env_vars',
                'profile_name': profile_name,
                'shell_type': shell_type
            })
            
            if shell_type.lower() in ["powershell", "pwsh"]:
                # PowerShell format
                print(f"$env:AWS_ACCESS_KEY_ID = '{credentials['aws_access_key_id']}'")
                print(f"$env:AWS_SECRET_ACCESS_KEY = '{credentials['aws_secret_access_key']}'")
                
                if "aws_session_token" in credentials:
                    print(f"$env:AWS_SESSION_TOKEN = '{credentials['aws_session_token']}'")
                else:
                    print("Remove-Item -Path 'Env:AWS_SESSION_TOKEN' -ErrorAction SilentlyContinue")
                    
                if "region" in credentials:
                    print(f"$env:AWS_DEFAULT_REGION = '{credentials['region']}'")
                    
                print("Write-Host '[OK] AWS environment variables set for profile: " + profile_name + "' -ForegroundColor Green")
                
            elif shell_type.lower() in ["cmd", "batch"]:
                # Command Prompt format
                print(f"set AWS_ACCESS_KEY_ID={credentials['aws_access_key_id']}")
                print(f"set AWS_SECRET_ACCESS_KEY={credentials['aws_secret_access_key']}")
                
                if "aws_session_token" in credentials:
                    print(f"set AWS_SESSION_TOKEN={credentials['aws_session_token']}")
                else:
                    print("set AWS_SESSION_TOKEN=")
                    
                if "region" in credentials:
                    print(f"set AWS_DEFAULT_REGION={credentials['region']}")
                    
                print(f"echo [OK] AWS environment variables set for profile: {profile_name}")
                
            elif shell_type.lower() in ["bash", "sh", "zsh"]:
                # Bash/Unix shell format
                print(f"export AWS_ACCESS_KEY_ID='{credentials['aws_access_key_id']}'")
                print(f"export AWS_SECRET_ACCESS_KEY='{credentials['aws_secret_access_key']}'")
                
                if "aws_session_token" in credentials:
                    print(f"export AWS_SESSION_TOKEN='{credentials['aws_session_token']}'")
                else:
                    print("unset AWS_SESSION_TOKEN")
                    
                if "region" in credentials:
                    print(f"export AWS_DEFAULT_REGION='{credentials['region']}'")
                    
                print(f"echo '[OK] AWS environment variables set for profile: {profile_name}'")
                
            else:
                raise ValueError(f"Unsupported shell type: {shell_type}")
                
        except Exception as e:
            logger.error(f"Error outputting environment variables: {e}")
            if shell_type and shell_type.lower() in ["powershell", "pwsh"]:
                print(
                    f"Write-Host '[ERROR] Error setting AWS environment variables: {e}' -ForegroundColor Red",
                    file=sys.stderr,
                )
            elif shell_type and shell_type.lower() in ["cmd", "batch"]:
                print(
                    f"echo [ERROR] Error setting AWS environment variables: {e}",
                    file=sys.stderr,
                )
            elif shell_type and shell_type.lower() in ["bash", "sh", "zsh"]:
                print(
                    f"echo '[ERROR] Error setting AWS environment variables: {e}'",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[ERROR] Error setting AWS environment variables: {e}",
                    file=sys.stderr,
                )
            sys.exit(1)


async def output_credentials_json(profile_name: str) -> None:
    """Output credentials in AWS credential_process JSON format."""
    manager = AWSCredentialManager()
    
    try:
        credentials = await manager.get_credentials(profile_name)
        
        # Format for AWS credential_process
        output = {
            "Version": 1,
            "AccessKeyId": credentials["aws_access_key_id"],
            "SecretAccessKey": credentials["aws_secret_access_key"]
        }
        
        if "aws_session_token" in credentials:
            output["SessionToken"] = credentials["aws_session_token"]
            
        print(json.dumps(output))

    except Exception as e:
        # Write error to stderr so it doesn't interfere with JSON output
        print(f"Error retrieving credentials: {e}", file=sys.stderr)
        sys.exit(1)


async def output_credentials_plaintext(profile_name: str) -> None:
    """Output credentials in plain text key=value format."""
    manager = AWSCredentialManager()

    try:
        credentials = await manager.get_credentials(profile_name)

        print(f"aws_access_key_id={credentials['aws_access_key_id']}")
        print(f"aws_secret_access_key={credentials['aws_secret_access_key']}")

        if "aws_session_token" in credentials:
            print(f"aws_session_token={credentials['aws_session_token']}")

        if "region" in credentials:
            print(f"region={credentials['region']}")

    except Exception as e:
        print(f"Error retrieving credentials: {e}", file=sys.stderr)
        sys.exit(1)


async def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="AWS Credentials Manager with Windows Hello Encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Add credentials for a profile
  python aws-hello-creds.py add-profile my-profile --access-key AKIA... --secret-key xyz123... --region us-east-1

  # Add credentials with session token (for temporary credentials)
  python aws-hello-creds.py add-profile temp-profile --access-key AKIA... --secret-key xyz123... --session-token IQoJ...

  # List all profiles
  python aws-hello-creds.py list-profiles

  # Get credentials (used by AWS CLI via credential_process)
  python aws-hello-creds.py get-credentials --profile my-profile

  # Set environment variables for terminal session
  python aws-hello-creds.py set-env my-profile
  python aws-hello-creds.py set-env my-profile --shell powershell
  python aws-hello-creds.py set-env my-profile --shell cmd
  python aws-hello-creds.py set-env my-profile --shell bash

  # Remove a profile
  python aws-hello-creds.py remove-profile my-profile

Credential Rotation Examples:
  # Check if credentials need rotation
  python aws-hello-creds.py check-rotation my-profile
  
  # Auto-rotate (detects credential type)
  python aws-hello-creds.py rotate-credentials my-profile
  
  # Manual rotation with new credentials
  python aws-hello-creds.py rotate-credentials my-profile --type manual \\
    --access-key AKIA... --secret-key SECRET...
  
  # List available backups
  python aws-hello-creds.py list-backups
  python aws-hello-creds.py list-backups --profile my-profile
  
  # Restore from backup
  python aws-hello-creds.py restore-backup my-profile 20250806_143000

AWS CLI Integration:
  After adding a profile, it will be automatically configured in ~/.aws/config
  You can then use it with: aws s3 ls --profile my-profile

Environment Variables for Terminal Sessions:
  The shell type is auto-detected, but you can override it if needed.
  Use the set-env command to set AWS environment variables for your current shell session:
  
  PowerShell (auto-detected):
    python aws-hello-creds.py set-env my-profile | Invoke-Expression
    
  Command Prompt (auto-detected):
    for /f "delims=" %i in ('python aws-hello-creds.py set-env my-profile') do %i
    
  Bash/WSL (auto-detected):
    eval "$(python aws-hello-creds.py set-env my-profile)"

Security Features:
  • Windows Hello biometric authentication for all operations
  • Hardware-backed credential encryption and storage
  • Automatic backup creation before credential rotation
  • Comprehensive audit logging for security compliance
  • Secure memory clearing of sensitive data
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Add profile command
    add_parser = subparsers.add_parser("add-profile", help="Add or update encrypted credentials for a profile")
    add_parser.add_argument("profile_name", help="AWS profile name")
    add_parser.add_argument("--access-key", required=True, help="AWS Access Key ID")
    add_parser.add_argument("--secret-key", required=True, help="AWS Secret Access Key")
    add_parser.add_argument("--session-token", help="AWS Session Token (for temporary credentials)")
    add_parser.add_argument("--region", help="Default AWS region for this profile")
    
    # Get credentials command (for credential_process)
    get_parser = subparsers.add_parser("get-credentials", help="Get credentials for a profile (credential_process format)")
    get_parser.add_argument("--profile", required=True, help="Profile name")

    # Export plain text credentials command
    export_parser = subparsers.add_parser(
        "export-profile",
        help="Export decrypted credentials for a profile in plain text"
    )
    export_parser.add_argument("profile_name", help="Profile name")

    # Set environment variables command
    env_parser = subparsers.add_parser("set-env", help="Output commands to set AWS environment variables")
    env_parser.add_argument("profile_name", help="Profile name")
    env_parser.add_argument("--shell", choices=["powershell", "pwsh", "cmd", "batch", "bash", "sh", "zsh"], 
                           help="Shell type for environment variable format (auto-detected if not specified)")
    
    # List profiles command
    subparsers.add_parser("list-profiles", help="List all available encrypted profiles")
    
    # Remove profile command
    remove_parser = subparsers.add_parser("remove-profile", help="Remove encrypted credentials for a profile")
    remove_parser.add_argument("profile_name", help="Profile name to remove")
    
    # Check rotation status command
    rotation_check_parser = subparsers.add_parser("check-rotation", help="Check if credentials need rotation")
    rotation_check_parser.add_argument("profile_name", help="Profile name to check")
    
    # Rotate credentials command
    rotate_parser = subparsers.add_parser("rotate-credentials", help="Rotate AWS credentials with backup")
    rotate_parser.add_argument("profile_name", help="Profile name to rotate")
    rotate_parser.add_argument("--type", choices=["auto", "manual", "temporary", "access-key"], 
                              default="auto", help="Rotation type (auto-detected if not specified)")
    rotate_parser.add_argument("--access-key", help="New AWS Access Key ID (for manual rotation)")
    rotate_parser.add_argument("--secret-key", help="New AWS Secret Access Key (for manual rotation)")
    rotate_parser.add_argument("--session-token", help="New AWS Session Token (for manual temporary rotation)")
    
    # List backups command
    backup_list_parser = subparsers.add_parser("list-backups", help="List available credential backups")
    backup_list_parser.add_argument("--profile", help="Filter backups for specific profile")
    
    # Restore from backup command
    restore_parser = subparsers.add_parser("restore-backup", help="Restore credentials from backup")
    restore_parser.add_argument("profile_name", help="Profile name to restore")
    restore_parser.add_argument("backup_timestamp", help="Backup timestamp (format: YYYYMMDD_HHMMSS)")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    manager = AWSCredentialManager()
    
    try:
        if args.command == "add-profile":
            await manager.add_profile(
                args.profile_name,
                args.access_key,
                args.secret_key,
                args.session_token,
                args.region
            )
            
        elif args.command == "get-credentials":
            await output_credentials_json(args.profile)

        elif args.command == "export-profile":
            await output_credentials_plaintext(args.profile_name)

        elif args.command == "set-env":
            await manager.output_env_vars(args.profile_name, args.shell)
            
        elif args.command == "list-profiles":
            await manager.list_profiles()
            
        elif args.command == "remove-profile":
            await manager.remove_profile(args.profile_name)
            
        elif args.command == "check-rotation":
            await manager.check_rotation_needed(args.profile_name)
            
        elif args.command == "rotate-credentials":
            await manager.rotate_credentials(
                args.profile_name,
                args.type,
                args.access_key,
                args.secret_key,
                args.session_token
            )
            
        elif args.command == "list-backups":
            await manager.list_backups(args.profile)
            
        elif args.command == "restore-backup":
            await manager.restore_from_backup(args.profile_name, args.backup_timestamp)
            
    except WindowsHelloError as e:
        print(f"❌ Windows Hello Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"❌ File Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected Error: {e}", file=sys.stderr)
        sys.exit(1)


def cli_main():
    """CLI entry point for console script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
