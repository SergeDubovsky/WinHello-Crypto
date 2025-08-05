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
from pathlib import Path
from typing import Dict, Optional, Union

from hello_crypto import FileEncryptor, WindowsHelloError


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)


class AWSCredentialManager:
    """Manages AWS credentials with Windows Hello encryption."""
    
    # AWS Access Key patterns for validation
    ACCESS_KEY_PATTERN = re.compile(r'^AKIA[0-9A-Z]{16}$')
    SECRET_KEY_PATTERN = re.compile(r'^[A-Za-z0-9/+=]{40}$')
    SESSION_TOKEN_PATTERN = re.compile(r'^[A-Za-z0-9/+=]{100,}$')
    PROFILE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9-_\.]+$')
    
    def __init__(self):
        self.encryptor = FileEncryptor(
            key_name="AWSCredentialKey",
            challenge="AWSCredentialChallenge"
        )
        self.aws_dir = Path.home() / ".aws"
        self.credentials_dir = self.aws_dir / "hello-encrypted"
        
    def _validate_profile_name(self, profile_name: str) -> None:
        """Validate AWS profile name format."""
        if not profile_name or not profile_name.strip():
            raise ValueError("Profile name cannot be empty")
        
        if not self.PROFILE_NAME_PATTERN.match(profile_name):
            raise ValueError(
                "Profile name can only contain letters, numbers, hyphens, underscores, and periods"
            )
        
        if len(profile_name) > 64:
            raise ValueError("Profile name cannot exceed 64 characters")
    
    def _validate_aws_credentials(self, access_key: str, secret_key: str, 
                                 session_token: Optional[str] = None) -> None:
        """Validate AWS credential format."""
        if not self.ACCESS_KEY_PATTERN.match(access_key):
            raise ValueError(
                "Invalid AWS Access Key format. Must start with 'AKIA' followed by 16 alphanumeric characters"
            )
        
        if not self.SECRET_KEY_PATTERN.match(secret_key):
            raise ValueError(
                "Invalid AWS Secret Key format. Must be 40 characters of base64-like characters"
            )
        
        if session_token and not self.SESSION_TOKEN_PATTERN.match(session_token):
            raise ValueError(
                "Invalid AWS Session Token format. Must be 100+ characters of base64-like characters"
            )
        
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
            
            if not await self.encryptor.is_supported():
                raise WindowsHelloError("Windows Hello is not supported on this device")
            
            logger.info(f"Adding profile '{profile_name}' with Windows Hello encryption")
            
            # Prepare credential data
            credential_data = {
                "aws_access_key_id": access_key,
                "aws_secret_access_key": secret_key,
                "created_at": asyncio.get_event_loop().time(),
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
                
            finally:
                self.encryptor.secure_clear(key_array)
                
        except ValueError as e:
            logger.error(f"Validation error: {e}")
            raise
        except WindowsHelloError as e:
            logger.error(f"Windows Hello error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error adding profile '{profile_name}': {e}")
            raise WindowsHelloError(f"Failed to add profile: {e}")
        
    async def _update_aws_config(self, profile_name: str, region: Optional[str] = None) -> None:
        """Update the AWS config file with credential_process."""
        try:
            config_file = self.aws_dir / "config"
            
            # Read existing config
            config_content = ""
            if config_file.exists():
                try:
                    config_content = config_file.read_text(encoding='utf-8')
                except UnicodeDecodeError:
                    logger.warning("AWS config file has encoding issues, treating as empty")
                    config_content = ""
                    
            # Profile section name
            profile_section = f"[profile {profile_name}]"
            
            # Get the path to this script
            script_path = Path(__file__).absolute()
            
            # Credential process command (escape Windows paths properly)
            credential_process = f'credential_process = python "{script_path}" get-credentials --profile {profile_name}'
            
            # Parse and update config more robustly
            lines = config_content.split('\n') if config_content else []
            new_lines = []
            in_target_profile = False
            profile_found = False
            
            for line in lines:
                line_stripped = line.strip()
                
                if line_stripped == profile_section:
                    in_target_profile = True
                    profile_found = True
                    new_lines.append(line)
                    new_lines.append(credential_process)
                    if region:
                        new_lines.append(f"region = {region}")
                    new_lines.append("output = json")
                    continue
                elif line_stripped.startswith('[') and in_target_profile:
                    in_target_profile = False
                
                # Skip existing credential_process, region, and output lines for this profile
                if in_target_profile and any(line_stripped.startswith(prefix) for prefix in 
                                           ['credential_process =', 'region =', 'output =']):
                    continue
                    
                if not in_target_profile:
                    new_lines.append(line)
                    
            # If profile wasn't found, add it
            if not profile_found:
                if new_lines and new_lines[-1].strip():
                    new_lines.append("")  # Add blank line before new profile
                new_lines.append(profile_section)
                new_lines.append(credential_process)
                if region:
                    new_lines.append(f"region = {region}")
                new_lines.append("output = json")
                
            # Write updated config atomically
            temp_config = config_file.with_suffix('.tmp')
            temp_config.write_text('\n'.join(new_lines), encoding='utf-8')
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
                    raise WindowsHelloError(f"Invalid credential data format: {e}")
                
                # Validate required fields
                required_fields = ["aws_access_key_id", "aws_secret_access_key"]
                missing_fields = [field for field in required_fields if field not in credential_data]
                if missing_fields:
                    raise WindowsHelloError(f"Missing required credential fields: {', '.join(missing_fields)}")
                
                logger.info(f"Successfully retrieved credentials for profile '{profile_name}'")
                return credential_data
                
            finally:
                self.encryptor.secure_clear(key_array)
                
        except WindowsHelloError:
            raise
        except ValueError as e:
            logger.error(f"Validation error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving credentials for '{profile_name}': {e}")
            raise WindowsHelloError(f"Failed to retrieve credentials: {e}")
        
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
        print(f"✅ Encrypted credentials for profile '{profile_name}' removed.")
        
        # Optionally remove from AWS config
        print(f"Note: You may want to manually remove the profile from ~/.aws/config")


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

  # Remove a profile
  python aws-hello-creds.py remove-profile my-profile

AWS CLI Integration:
  After adding a profile, it will be automatically configured in ~/.aws/config
  You can then use it with: aws s3 ls --profile my-profile
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
    
    # List profiles command
    subparsers.add_parser("list-profiles", help="List all available encrypted profiles")
    
    # Remove profile command
    remove_parser = subparsers.add_parser("remove-profile", help="Remove encrypted credentials for a profile")
    remove_parser.add_argument("profile_name", help="Profile name to remove")
    
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
            
        elif args.command == "list-profiles":
            await manager.list_profiles()
            
        elif args.command == "remove-profile":
            await manager.remove_profile(args.profile_name)
            
    except WindowsHelloError as e:
        print(f"❌ Windows Hello Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"❌ File Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
