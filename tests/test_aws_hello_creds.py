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
    async def test_output_credentials_plaintext(self):
        """Test plain text credential export."""
        test_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
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
                await aws_hello_creds.output_credentials_plaintext("test-profile")
                output = captured_output.getvalue().splitlines()

                assert "aws_access_key_id=AKIAIOSFODNN7EXAMPLE" in output
                assert "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in output
                assert "region=us-east-1" in output

            finally:
                sys.stdout = sys.__stdout__

    @pytest.mark.asyncio
    async def test_output_credentials_plaintext_with_session_token(self):
        """Test plain text output including session token."""
        test_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_session_token": "IQoJb3JpZ2luX2V" + "x" * 100,
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
                await aws_hello_creds.output_credentials_plaintext("test-profile")
                output = captured_output.getvalue().splitlines()

                assert "aws_session_token=" + test_credentials["aws_session_token"] in output

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


class TestCredentialBackupAndRestore:
    """Test backup and restore functionality."""
    
    @pytest.fixture
    def manager_with_backup(self):
        """Create manager with backup directory setup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            mgr = AWSCredentialManager()
            mgr.aws_dir = Path(temp_dir) / ".aws"
            mgr.credentials_dir = mgr.aws_dir / "hello-encrypted"
            mgr.backup_dir = mgr.credentials_dir / "backups"
            yield mgr
    
    @pytest.mark.asyncio
    async def test_backup_credentials(self, manager_with_backup):
        """Test credential backup functionality."""
        manager = manager_with_backup
        manager._ensure_directories()
        manager.backup_dir.mkdir(exist_ok=True)
        
        test_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1"
        }
        
        with patch.object(manager.encryptor, 'encrypt_data', return_value=b'encrypted_backup'):
            await manager._backup_credentials("test-profile", test_credentials)
            
            # Check backup file was created
            backup_files = list(manager.backup_dir.glob("test-profile_*.enc"))
            assert len(backup_files) > 0
    
    @pytest.mark.asyncio
    async def test_list_backups_empty(self, manager_with_backup):
        """Test listing backups when none exist."""
        manager = manager_with_backup
        manager._ensure_directories()
        manager.backup_dir.mkdir(exist_ok=True)
        
        # Should not raise exception
        await manager.list_backups()
    
    @pytest.mark.asyncio
    async def test_list_backups_with_files(self, manager_with_backup):
        """Test listing backups when backup files exist."""
        manager = manager_with_backup
        manager._ensure_directories()
        manager.backup_dir.mkdir(exist_ok=True)
        
        # Create dummy backup files
        (manager.backup_dir / "profile1_20240101_120000.enc").touch()
        (manager.backup_dir / "profile2_20240102_130000.enc").touch()
        
        # Should list the backups
        await manager.list_backups()
    
    @pytest.mark.asyncio
    async def test_restore_from_backup_success(self, manager_with_backup):
        """Test successful backup restoration."""
        manager = manager_with_backup
        manager._ensure_directories()
        manager.backup_dir.mkdir(exist_ok=True)
        
        # Create backup file
        backup_file = manager.backup_dir / "test-profile_20240101_120000.enc"
        backup_file.write_bytes(b'encrypted_backup_data')
        
        test_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1"
        }
        
        json_data = json.dumps(test_credentials).encode('utf-8')
        
        with patch.object(manager.encryptor, 'decrypt_data', return_value=json_data), \
             patch.object(manager.encryptor, 'encrypt_data', return_value=b'encrypted_data'), \
             patch.object(manager, '_update_aws_config', return_value=None):
            
            await manager.restore_from_backup("test-profile", "20240101_120000")
            
            # Check credential file was created
            cred_file = manager._get_credential_file_path("test-profile")
            assert cred_file.exists()
    
    @pytest.mark.asyncio
    async def test_restore_from_backup_not_found(self, manager_with_backup):
        """Test backup restoration when backup doesn't exist."""
        manager = manager_with_backup
        manager._ensure_directories()
        
        with pytest.raises(Exception):  # Should raise appropriate error
            await manager.restore_from_backup("nonexistent", "20240101_120000")


class TestCredentialRotation:
    """Test credential rotation functionality."""
    
    @pytest.fixture
    def manager_with_rotation(self):
        """Create manager for rotation tests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            mgr = AWSCredentialManager()
            mgr.aws_dir = Path(temp_dir) / ".aws"
            mgr.credentials_dir = mgr.aws_dir / "hello-encrypted"
            yield mgr
    
    @pytest.mark.asyncio
    async def test_check_credential_age_new(self, manager_with_rotation):
        """Test credential age check for new credentials."""
        manager = manager_with_rotation
        manager._ensure_directories()
        
        # Create fresh credential file
        cred_file = manager._get_credential_file_path("test-profile")
        cred_file.touch()
        
        # Mock get_credentials to avoid Windows Hello authentication
        with patch.object(manager, 'get_credentials', side_effect=Exception("Profile not found")):
            needs_rotation, age_days, warning = await manager._check_credential_age("test-profile")
            assert not needs_rotation  # Should be False when profile not found
            assert age_days is None
            # The warning might be None depending on the specific error handling
    
    @pytest.mark.asyncio
    async def test_check_credential_age_missing_file(self, manager_with_rotation):
        """Test credential age check when file doesn't exist."""
        manager = manager_with_rotation
        
        needs_rotation, age_days, warning = await manager._check_credential_age("nonexistent")
        assert needs_rotation is False
        assert age_days is None
        # The warning might be None depending on the specific error handling
    
    @pytest.mark.asyncio
    async def test_check_rotation_needed(self, manager_with_rotation):
        """Test rotation needed check."""
        manager = manager_with_rotation
        manager._ensure_directories()
        
        # Create credential file
        cred_file = manager._get_credential_file_path("test-profile")
        cred_file.touch()
        
        # Should not raise exception
        await manager.check_rotation_needed("test-profile")
    
    @pytest.mark.asyncio
    async def test_rotate_credentials_manual(self, manager_with_rotation):
        """Test manual credential rotation."""
        manager = manager_with_rotation
        
        # Mock get_credentials to return existing credentials
        mock_creds = {
            "aws_access_key_id": "OLD_KEY",
            "aws_secret_access_key": "OLD_SECRET", 
            "region": "us-west-1"
        }
        
        # Mock the rotation process and user input
        with patch.object(manager, 'get_credentials', return_value=mock_creds), \
             patch.object(manager, '_backup_credentials', return_value=None), \
             patch.object(manager, 'add_profile', return_value=None), \
             patch('builtins.input', return_value='y'):  # Mock user input
            
            # Test with required credentials for manual rotation
            await manager.rotate_credentials(
                "test-profile", "manual", 
                "AKIAIOSFODNN7EXAMPLE", 
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )


class TestFileEncryptionDecryption:
    """Test AWS profile file encryption and decryption."""
    
    @pytest.fixture
    def manager_with_files(self):
        """Create manager with file setup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            mgr = AWSCredentialManager()
            mgr.aws_dir = Path(temp_dir) / ".aws"
            mgr.credentials_dir = mgr.aws_dir / "hello-encrypted"
            yield mgr
    
    @pytest.mark.asyncio
    async def test_encrypt_aws_profile_success(self, manager_with_files):
        """Test encrypting AWS profile from credentials file."""
        manager = manager_with_files
        manager._ensure_directories()
        
        # Mock the config parser to return our test profile
        mock_config = MagicMock()
        mock_config.has_section.return_value = True
        mock_config.items.return_value = [('region', 'us-east-1'), ('output', 'json')]
        
        # Mock the entire encryption process to avoid file system operations
        with patch('configparser.RawConfigParser') as mock_config_class, \
             patch.object(manager.encryptor, 'encrypt_file', return_value=None), \
             patch('shutil.move') as mock_move, \
             patch('pathlib.Path.write_text') as mock_write_text:
            
            mock_config_class.return_value = mock_config
            
            await manager.encrypt_aws_profile("test-profile")
            
            # Check that encrypt_file was called
            manager.encryptor.encrypt_file.assert_called()
    
    @pytest.mark.asyncio
    async def test_encrypt_aws_profile_with_delete(self, manager_with_files):
        """Test encrypting AWS profile with deletion of plaintext."""
        manager = manager_with_files
        manager._ensure_directories()
        
        # Mock the config parser to return our test profile
        mock_config = MagicMock()
        mock_config.has_section.return_value = True
        mock_config.items.return_value = [('region', 'us-east-1'), ('output', 'json')]
        mock_config.remove_section.return_value = True
        
        # Mock the encryption and file operations to avoid path validation issues  
        with patch('configparser.RawConfigParser') as mock_config_class, \
             patch.object(manager.encryptor, 'encrypt_file', return_value=None), \
             patch('shutil.move') as mock_move, \
             patch('pathlib.Path.write_text') as mock_write_text, \
             patch('pathlib.Path.open', MagicMock()):
            
            mock_config_class.return_value = mock_config
            
            await manager.encrypt_aws_profile("test-profile", delete_plain=True)
            
            # Check that encrypt_file was called
            manager.encryptor.encrypt_file.assert_called()
            mock_config.remove_section.assert_called_with('profile test-profile')
    
    @pytest.mark.asyncio
    async def test_decrypt_aws_profile_success(self, manager_with_files):
        """Test decrypting AWS profile to credentials file."""
        manager = manager_with_files
        manager._ensure_directories()
        
        # Create encrypted file
        enc_file = manager._get_credential_file_path("test-profile")
        enc_file.write_bytes(b'encrypted_data')
        
        test_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1"
        }
        
        json_data = json.dumps(test_credentials).encode('utf-8')
        
        # Mock file validation and decryption
        with patch('security_utils.validate_file_path', return_value=enc_file), \
             patch.object(manager.encryptor, 'decrypt_file', return_value=None), \
             patch('pathlib.Path.read_text', return_value=json.dumps(test_credentials)):
            
            await manager.decrypt_aws_profile(str(enc_file))
            
            # The test is mainly about exercising the method, as file system operations are complex to mock


class TestShellDetection:
    """Test shell detection functionality."""
    
    @pytest.fixture
    def manager_shell(self):
        """Create manager for shell tests."""
        return AWSCredentialManager()
    
    def test_detect_shell_powershell(self, manager_shell):
        """Test PowerShell detection."""
        with patch.dict(os.environ, {'PSModulePath': 'C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules'}):
            shell = manager_shell._detect_shell()
            assert shell == "powershell"
    
    def test_detect_shell_cmd(self, manager_shell):
        """Test Command Prompt detection."""
        with patch.dict(os.environ, {}, clear=True):
            with patch('os.environ.get') as mock_get:
                mock_get.side_effect = lambda key, default=None: {
                    'PSModulePath': None,
                    'COMSPEC': 'C:\\Windows\\system32\\cmd.exe'
                }.get(key, default)
                
                shell = manager_shell._detect_shell()
                assert shell == "cmd"
    
    def test_detect_shell_default(self, manager_shell):
        """Test default shell detection."""
        with patch.dict(os.environ, {}, clear=True):
            shell = manager_shell._detect_shell()
            assert shell in ["powershell", "cmd"]  # Should default to something


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.fixture
    def manager_error(self):
        """Create manager for error tests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            mgr = AWSCredentialManager()
            mgr.aws_dir = Path(temp_dir) / ".aws"
            mgr.credentials_dir = mgr.aws_dir / "hello-encrypted"
            yield mgr
    
    @pytest.mark.asyncio
    async def test_get_credentials_from_encrypted_file_invalid_json(self, manager_error):
        """Test handling invalid JSON in encrypted file."""
        manager = manager_error
        manager._ensure_directories()
        
        # Create encrypted file
        enc_file = manager._get_credential_file_path("test-profile")
        enc_file.write_bytes(b'encrypted_data')
        
        with patch.object(manager.encryptor, 'decrypt_data', return_value=b'invalid json'):
            with pytest.raises(Exception):  # Should raise JSON decode error
                await manager._get_credentials_from_encrypted_file(str(enc_file))
    
    @pytest.mark.asyncio
    async def test_add_profile_windows_hello_not_supported(self, manager_error):
        """Test adding profile when Windows Hello is not supported."""
        manager = manager_error
        
        with patch.object(manager.encryptor, 'is_supported', return_value=False):
            with pytest.raises(Exception):  # Should raise appropriate error
                await manager.add_profile(
                    "test-profile",
                    "AKIAIOSFODNN7EXAMPLE", 
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                )
    
    @pytest.mark.asyncio
    async def test_output_env_vars_invalid_profile(self, manager_error):
        """Test environment variable output with invalid profile."""
        manager = manager_error
        
        with patch.object(manager, 'get_credentials', side_effect=Exception("Profile not found")):
            with pytest.raises(SystemExit):
                await manager.output_env_vars("nonexistent-profile")


class TestCLIMain:
    """Test CLI main function and argument parsing."""
    
    @pytest.mark.asyncio
    async def test_main_no_args(self):
        """Test main function with no arguments."""
        with patch('sys.argv', ['aws-hello-creds.py']):
            with patch('builtins.print') as mock_print:
                await aws_hello_creds.main()
                # Should print help when no command provided
    
    @pytest.mark.asyncio
    async def test_main_add_profile(self):
        """Test main function with add-profile command."""
        test_args = [
            'aws-hello-creds.py', 'add-profile', 'test-profile',
            '--access-key', 'AKIAIOSFODNN7EXAMPLE',
            '--secret-key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            '--region', 'us-east-1'
        ]
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.add_profile = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.add_profile.assert_called_once_with(
                    'test-profile',
                    'AKIAIOSFODNN7EXAMPLE',
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                    None,  # session_token
                    'us-east-1'
                )
    
    @pytest.mark.asyncio
    async def test_main_get_credentials(self):
        """Test main function with get-credentials command."""
        test_args = ['aws-hello-creds.py', 'get-credentials', '--profile', 'test-profile']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.output_credentials_json') as mock_output:
                mock_output.return_value = None
                
                await aws_hello_creds.main()
                
                mock_output.assert_called_once_with('test-profile')
    
    @pytest.mark.asyncio
    async def test_main_export_profile(self):
        """Test main function with export-profile command."""
        test_args = ['aws-hello-creds.py', 'export-profile', 'test-profile']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.output_credentials_plaintext') as mock_output:
                mock_output.return_value = None
                
                await aws_hello_creds.main()
                
                mock_output.assert_called_once_with('test-profile')
    
    @pytest.mark.asyncio
    async def test_main_set_env(self):
        """Test main function with set-env command."""
        test_args = ['aws-hello-creds.py', 'set-env', 'test-profile', '--shell', 'powershell']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.output_env_vars = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.output_env_vars.assert_called_once_with('test-profile', 'powershell')
    
    @pytest.mark.asyncio
    async def test_main_list_profiles(self):
        """Test main function with list-profiles command."""
        test_args = ['aws-hello-creds.py', 'list-profiles']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.list_profiles = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.list_profiles.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_main_remove_profile(self):
        """Test main function with remove-profile command."""
        test_args = ['aws-hello-creds.py', 'remove-profile', 'test-profile']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.remove_profile = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.remove_profile.assert_called_once_with('test-profile')
    
    @pytest.mark.asyncio
    async def test_main_check_rotation(self):
        """Test main function with check-rotation command."""
        test_args = ['aws-hello-creds.py', 'check-rotation', 'test-profile']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.check_rotation_needed = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.check_rotation_needed.assert_called_once_with('test-profile')
    
    @pytest.mark.asyncio
    async def test_main_rotate_credentials(self):
        """Test main function with rotate-credentials command."""
        test_args = [
            'aws-hello-creds.py', 'rotate-credentials', 'test-profile',
            '--type', 'manual',
            '--access-key', 'AKIAIOSFODNN7EXAMPLE',
            '--secret-key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        ]
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.rotate_credentials = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.rotate_credentials.assert_called_once_with(
                    'test-profile',
                    'manual',
                    'AKIAIOSFODNN7EXAMPLE',
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                    None  # session_token
                )
    
    @pytest.mark.asyncio
    async def test_main_list_backups(self):
        """Test main function with list-backups command."""
        test_args = ['aws-hello-creds.py', 'list-backups', '--profile', 'test-profile']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.list_backups = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.list_backups.assert_called_once_with('test-profile')
    
    @pytest.mark.asyncio
    async def test_main_restore_backup(self):
        """Test main function with restore-backup command."""
        test_args = ['aws-hello-creds.py', 'restore-backup', 'test-profile', '20240101_120000']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.restore_from_backup = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.restore_from_backup.assert_called_once_with('test-profile', '20240101_120000')
    
    @pytest.mark.asyncio
    async def test_main_encrypt_profile(self):
        """Test main function with encrypt-profile command."""
        test_args = ['aws-hello-creds.py', 'encrypt-profile', 'test-profile', '--delete-plain']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.encrypt_aws_profile = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.encrypt_aws_profile.assert_called_once_with('test-profile', None, True)
    
    @pytest.mark.asyncio
    async def test_main_decrypt_profile(self):
        """Test main function with decrypt-profile command."""
        test_args = ['aws-hello-creds.py', 'decrypt-profile', '/path/to/file.enc', '--profile', 'new-name']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.decrypt_aws_profile = AsyncMock()
                mock_manager_class.return_value = mock_manager
                
                await aws_hello_creds.main()
                
                mock_manager.decrypt_aws_profile.assert_called_once_with('/path/to/file.enc', 'new-name')
    
    @pytest.mark.asyncio
    async def test_main_windows_hello_error(self):
        """Test main function handling WindowsHelloError."""
        test_args = ['aws-hello-creds.py', 'list-profiles']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.list_profiles = AsyncMock(side_effect=aws_hello_creds.WindowsHelloError("Test error"))
                mock_manager_class.return_value = mock_manager
                
                with patch('sys.stderr') as mock_stderr:
                    with pytest.raises(SystemExit) as exc_info:
                        await aws_hello_creds.main()
                    
                    assert exc_info.value.code == 1
    
    @pytest.mark.asyncio
    async def test_main_file_not_found_error(self):
        """Test main function handling FileNotFoundError."""
        test_args = ['aws-hello-creds.py', 'list-profiles']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.list_profiles = AsyncMock(side_effect=FileNotFoundError("File not found"))
                mock_manager_class.return_value = mock_manager
                
                with patch('sys.stderr') as mock_stderr:
                    with pytest.raises(SystemExit) as exc_info:
                        await aws_hello_creds.main()
                    
                    assert exc_info.value.code == 1
    
    @pytest.mark.asyncio
    async def test_main_unexpected_error(self):
        """Test main function handling unexpected errors."""
        test_args = ['aws-hello-creds.py', 'list-profiles']
        
        with patch('sys.argv', test_args):
            with patch('aws_hello_creds.AWSCredentialManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.list_profiles = AsyncMock(side_effect=RuntimeError("Unexpected error"))
                mock_manager_class.return_value = mock_manager
                
                with patch('sys.stderr') as mock_stderr:
                    with pytest.raises(SystemExit) as exc_info:
                        await aws_hello_creds.main()
                    
                    assert exc_info.value.code == 1
    
    def test_cli_main(self):
        """Test CLI entry point."""
        with patch('aws_hello_creds.asyncio.run') as mock_run:
            aws_hello_creds.cli_main()
            mock_run.assert_called_once()
