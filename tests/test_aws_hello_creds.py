"""
Unit tests for aws_hello_creds module
"""

import pytest
import tempfile
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
import ctypes

if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
if hasattr(ctypes, "windll"):
    if not hasattr(ctypes.windll, "user32"):
        ctypes.windll.user32 = MagicMock()
    if not hasattr(ctypes.windll, "kernel32"):
        ctypes.windll.kernel32 = MagicMock()

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # Import the module under test
    import aws_hello_creds
    from aws_hello_creds import AWSCredentialManager
except Exception as e:
    pytest.skip(f"Could not import aws_hello_creds: {e}", allow_module_level=True)

class TestAWSCredentialManager:
    """Test AWS credential manager functionality."""
    
    @pytest.fixture
    def manager(self):
        # Create manager with temporary directory
        mgr = AWSCredentialManager()
        with tempfile.TemporaryDirectory() as temp_dir:
            mgr.aws_dir = Path(temp_dir) / ".aws"
            mgr.credentials_dir = mgr.aws_dir / "hello-encrypted"
            yield mgr
    
    def test_validate_profile_name_valid(self, manager):
        """Test valid profile name validation."""
        # These should not raise exceptions
        manager._validate_profile_name("valid-profile")
        manager._validate_profile_name("profile123")
        manager._validate_profile_name("my.profile")
        manager._validate_profile_name("test_profile")
    
    def test_validate_profile_name_invalid(self, manager):
        """Test invalid profile name validation."""
        with pytest.raises(Exception):  # Could be ValidationError or ValueError
            manager._validate_profile_name("")
        
        with pytest.raises(Exception):
            manager._validate_profile_name("   ")
        
        with pytest.raises(Exception):
            manager._validate_profile_name("profile with spaces")
        
        with pytest.raises(Exception):
            manager._validate_profile_name("a" * 65)
    
    def test_validate_aws_credentials_valid(self, manager):
        """Test valid AWS credential validation."""
        # Should not raise exception
        manager._validate_aws_credentials(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        
        # With session token
        manager._validate_aws_credentials(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "IQoJb3JpZ2luX2VjEHoaCXVzLWVhc3QtMSJIMEYCIQD" + "x" * 100
        )
    
    def test_validate_aws_credentials_invalid(self, manager):
        """Test invalid AWS credential validation."""
        with pytest.raises(Exception):  # Could be ValidationError or ValueError
            manager._validate_aws_credentials(
                "INVALID_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )
        
        with pytest.raises(Exception):
            manager._validate_aws_credentials(
                "AKIAIOSFODNN7EXAMPLE",
                "invalid_secret"
            )
        
        with pytest.raises(Exception):
            manager._validate_aws_credentials(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "short_token"
            )
    
    @pytest.mark.asyncio
    async def test_add_profile_success(self, manager):
        """Test successful profile addition."""
        with patch.object(manager.encryptor, 'is_supported', return_value=True), \
             patch.object(manager.encryptor, 'ensure_key_exists', return_value=None), \
             patch.object(manager.encryptor, 'derive_key_from_signature', return_value=b'x' * 32), \
             patch.object(manager.encryptor, 'encrypt_data', return_value=b'encrypted_data'), \
             patch.object(manager, '_update_aws_config', return_value=None):
            
            await manager.add_profile(
                "test-profile",
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                region="us-east-1"
            )
            
            # Check that credential file was created
            cred_file = manager._get_credential_file_path("test-profile")
            assert cred_file.exists()
    
    @pytest.mark.asyncio
    async def test_get_credentials_success(self, manager):
        """Test successful credential retrieval."""
        # First add a profile
        test_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "profile_name": "test-profile"
        }
        
        json_data = json.dumps(test_credentials).encode('utf-8')
        
        with patch.object(manager.encryptor, 'is_supported', return_value=True), \
             patch.object(manager.encryptor, 'derive_key_from_signature', return_value=b'x' * 32), \
             patch.object(manager.encryptor, 'decrypt_data', return_value=json_data):
            
            # Create a dummy credential file
            cred_file = manager._get_credential_file_path("test-profile")
            cred_file.parent.mkdir(parents=True, exist_ok=True)
            cred_file.write_bytes(b'dummy_encrypted_data')
            
            # Get credentials
            result = await manager.get_credentials("test-profile")
            
            assert result["aws_access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
            assert result["aws_secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    @pytest.mark.asyncio
    async def test_get_credentials_file_not_found(self, manager):
        """Test credential retrieval when file doesn't exist."""
        with pytest.raises(Exception):  # Could be WindowsHelloError or FileNotFoundError
            await manager.get_credentials("nonexistent-profile")
    
    @pytest.mark.asyncio
    async def test_list_profiles_empty(self, manager):
        """Test listing profiles when none exist."""
        # This should not raise an exception
        await manager.list_profiles()
    
    @pytest.mark.asyncio
    async def test_list_profiles_with_profiles(self, manager):
        """Test listing profiles when some exist."""
        # Create dummy credential files
        manager._ensure_directories()
        (manager.credentials_dir / "profile1.enc").touch()
        (manager.credentials_dir / "profile2.enc").touch()
        
        # This should list the profiles (captured in stdout)
        await manager.list_profiles()
    
    @pytest.mark.asyncio
    async def test_remove_profile_success(self, manager):
        """Test successful profile removal."""
        # Create dummy credential file
        manager._ensure_directories()
        cred_file = manager._get_credential_file_path("test-profile")
        cred_file.touch()
        
        assert cred_file.exists()
        await manager.remove_profile("test-profile")
        assert not cred_file.exists()
    
    @pytest.mark.asyncio
    async def test_remove_profile_not_found(self, manager):
        """Test removing profile that doesn't exist."""
        # Should not raise exception, just print message
        await manager.remove_profile("nonexistent-profile")
    
    def test_get_credential_file_path(self, manager):
        """Test credential file path generation."""
        path = manager._get_credential_file_path("test-profile")
        assert path.name == "test-profile.enc"
        assert "hello-encrypted" in str(path)
    
    def test_ensure_directories(self, manager):
        """Test directory creation."""
        manager._ensure_directories()
        assert manager.aws_dir.exists()
        assert manager.credentials_dir.exists()

    @pytest.mark.asyncio
    async def test_output_env_vars_failure_before_shell_detection(self, manager):
        """Test handler when failure occurs before shell detection."""
        import io
        import sys

        with patch.object(manager, 'get_credentials', side_effect=RuntimeError("Test error")):
            captured_err = io.StringIO()
            sys.stderr = captured_err
            try:
                with pytest.raises(SystemExit) as exc_info:
                    await manager.output_env_vars("test-profile")
            finally:
                sys.stderr = sys.__stderr__

        assert "[ERROR] Error setting AWS environment variables: Test error" in captured_err.getvalue()
        assert exc_info.value.code == 1

class TestCLIFunctions:
    """Test CLI functions."""
    
    @pytest.mark.asyncio
    async def test_output_credentials_json(self):
        """Test JSON credential output for AWS CLI."""
        test_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }
        
        with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager.get_credentials = AsyncMock(return_value=test_credentials)
            mock_manager_class.return_value = mock_manager
            
            # Capture stdout
            import io
            import sys
            captured_output = io.StringIO()
            sys.stdout = captured_output
            
            try:
                await aws_hello_creds.output_credentials_json("test-profile")
                output = captured_output.getvalue()
                
                # Parse the JSON output
                result = json.loads(output)
                assert result["Version"] == 1
                assert result["AccessKeyId"] == "AKIAIOSFODNN7EXAMPLE"
                assert result["SecretAccessKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                
            finally:
                sys.stdout = sys.__stdout__
    
    @pytest.mark.asyncio
    async def test_output_credentials_json_with_session_token(self):
        """Test JSON credential output with session token."""
        test_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_session_token": "IQoJb3JpZ2luX2V" + "x" * 100
        }
        
        with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager.get_credentials = AsyncMock(return_value=test_credentials)
            mock_manager_class.return_value = mock_manager
            
            import io
            import sys
            captured_output = io.StringIO()
            sys.stdout = captured_output
            
            try:
                await aws_hello_creds.output_credentials_json("test-profile")
                output = captured_output.getvalue()
                
                result = json.loads(output)
                assert "SessionToken" in result
                assert result["SessionToken"] == test_credentials["aws_session_token"]
                
            finally:
                sys.stdout = sys.__stdout__

class TestConfigFileManagement:
    """Test AWS config file management."""
    
    @pytest.fixture
    def manager_with_temp_config(self):
        """Create manager with temporary AWS config directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            mgr = AWSCredentialManager()
            mgr.aws_dir = Path(temp_dir) / ".aws"
            mgr.credentials_dir = mgr.aws_dir / "hello-encrypted"
            yield mgr
    
    @pytest.mark.asyncio
    async def test_update_aws_config_new_profile(self, manager_with_temp_config):
        """Test adding new profile to AWS config."""
        manager = manager_with_temp_config
        manager._ensure_directories()
        
        await manager._update_aws_config("test-profile", "us-east-1")
        
        config_file = manager.aws_dir / "config"
        assert config_file.exists()
        
        config_content = config_file.read_text()
        assert "[profile test-profile]" in config_content
        assert "credential_process" in config_content
        assert "region = us-east-1" in config_content
    
    @pytest.mark.asyncio
    async def test_update_aws_config_existing_profile(self, manager_with_temp_config):
        """Test updating existing profile in AWS config."""
        manager = manager_with_temp_config
        manager._ensure_directories()
        
        # Create initial config
        config_file = manager.aws_dir / "config" 
        config_file.write_text("""[profile test-profile]
credential_process = old_command
region = us-west-1
output = json

[profile other-profile]
region = us-east-1
""")
        
        # Update the profile
        await manager._update_aws_config("test-profile", "us-east-2")
        
        config_content = config_file.read_text()
        assert "region = us-east-2" in config_content
        assert "old_command" not in config_content
        assert "[profile other-profile]" in config_content  # Should preserve other profiles

    @pytest.mark.asyncio
    async def test_update_aws_config_preserves_comments_and_no_duplicates(self, manager_with_temp_config):
        """Ensure comments are preserved and keys aren't duplicated."""
        manager = manager_with_temp_config
        manager._ensure_directories()

        config_file = manager.aws_dir / "config"
        config_file.write_text(
            """[profile test]
region = us-west-2
# important comment
output = json
""",
            encoding="utf-8",
        )

        await manager._update_aws_config("test", "us-east-1")
        await manager._update_aws_config("test", "us-east-1")

        content = config_file.read_text()
        assert "# important comment" in content
        assert content.count("credential_process") == 1
        assert content.count("region = us-east-1") == 1
        assert content.count("output = json") == 1

if __name__ == "__main__":
    pytest.main([__file__])
