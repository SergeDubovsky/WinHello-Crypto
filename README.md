# WinHello-Crypto

[![CI Tests](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/ci.yml)
[![Security Tests](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/security-tests.yml/badge.svg)](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/security-tests.yml)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green.svg)](https://github.com/SergeDubovsky/WinHello-Crypto)
[![Encryption](https://img.shields.io/badge/Encryption-AES%20256%20GCM%20%2B%20Argon2id-blue.svg)](https://github.com/SergeDubovsky/WinHello-Crypto)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-lightgrey.svg)](https://github.com/SergeDubovsky/WinHello-Crypto)
[![Python](https://img.shields.io/badge/Python-3.7%2B-yellow.svg)](https://github.com/SergeDubovsky/WinHello-Crypto)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://github.com/SergeDubovsky/WinHello-Crypto/blob/main/LICENSE)

**Enterprise-Grade AWS Credential Security with Windows Hello Biometric Authentication**

A revolutionary approach to AWS credential management that **eliminates plaintext storage vulnerabilities** by leveraging Windows Hello's hardware-backed biometric authentication. This tool transforms credential security from a liability into a robust, user-friendly protection layer.

## The Problem We Solve

Traditional AWS credential storage methods expose organizations to significant security risks:
- **Plaintext credentials** in `~/.aws/credentials` files
- **Environment variables** stored in shell profiles  
- **Hardcoded keys** in configuration files
- **Complex certificate management** with potential key exposure
- **Credential theft** from compromised developer machines
- **No audit trail** for credential access

## Our Solution

WinHello-Crypto provides **hardware-backed credential protection** that:

- **Eliminates plaintext storage** - Zero credentials stored in readable format
- **Requires biometric authentication** - Each access needs fingerprint/face/PIN
- **Provides seamless integration** - Works transparently with existing AWS CLI workflows
- **Offers enterprise-grade encryption** - AES-256-GCM + Argon2id + authenticated encryption
- **Ensures memory safety** - Secure clearing of sensitive data from memory
- **Maintains audit trails** - Comprehensive logging without credential exposure

## Security Impact & Benefits

### **Before WinHello-Crypto:**
```bash
# Traditional approach - SECURITY RISK
$ cat ~/.aws/credentials
[default]
aws_access_key_id = AKIA1234567890EXAMPLE      # ← PLAINTEXT EXPOSURE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### **After WinHello-Crypto:**
```bash
# Secure approach - BIOMETRIC PROTECTED
$ aws s3 ls --profile my-secure-profile
# ↑ Triggers Windows Hello biometric prompt
# ↑ Credentials decrypted only in memory
# ↑ Zero plaintext storage anywhere
```

### **Quantified Security Improvements:**

- **100% reduction** in plaintext credential exposure
- **Hardware-backed protection** using TPM/Secure Enclave
- **Real-time biometric verification** for each access
- **OWASP-compliant** secure coding practices
- **Enterprise audit trails** without credential leakage
- **Memory-safe operations** with secure data clearing

## Features

- **Biometric Authentication**: Uses Windows Hello for secure key derivation
- **Strong Encryption**: AES-256-GCM with authenticated encryption and integrity protection
- **Hardware-Backed Security**: Encryption keys derived from Windows Hello signatures
- **Memory Safety**: Secure memory clearing of sensitive data
- **File Operations**: Encrypt and decrypt any file type
- **AWS Credentials Manager**: Securely store and retrieve AWS credentials
- **AWS CLI Integration**: Seamless integration with AWS CLI credential_process
- **Environment Variable Support**: Set AWS credentials as environment variables for shell sessions
- **Multi-Shell Support**: Automatic detection of PowerShell, CMD, and Bash shells
- **Enhanced UX**: Automatic Windows Hello dialog activation for seamless biometric authentication
- **Credential Rotation**: Comprehensive rotation system with automatic backups and rollback support
- **Backup Management**: Encrypted backup storage with timestamped restore points
- **Rotation Monitoring**: Automatic detection of aging credentials with rotation recommendations
- **Async Operations**: Non-blocking file operations

## What's New in v2.1.7

### Enhanced Profile Management

- **Simplified Profile Architecture**: Eliminated complex profile name mapping logic for more predictable behavior
- **Direct File Naming**: Profile names now match encrypted file names exactly (e.g., `my-profile` uses `my-profile.enc`)
- **Improved export-profile Command**: Fixed profile name resolution issues and streamlined credential export functionality
- **Dual Format Support**: Enhanced compatibility with both direct credential format and full profile format storage
- **Better Error Handling**: More descriptive error messages for profile-related operations

### Bug Fixes

- Fixed profile name mapping inconsistencies between `get-credentials` and `export-profile` commands
- Resolved credential format compatibility issues for profiles created with different storage methods
- Improved credential validation and error reporting

### Technical Improvements

- Streamlined codebase with reduced complexity in profile name resolution
- Enhanced test coverage for profile management operations
- Better separation of concerns between credential storage formats

## Components

### 1. File Encryption (`hello_crypto.py`)

Basic file encryption and decryption using Windows Hello authentication.

### 2. AWS Credentials Manager (`aws_hello_creds.py`)

Specialized tool for managing AWS credentials with Windows Hello encryption, designed to replace certificate-based credential storage.

## Requirements

- Windows 10/11 with Windows Hello enabled
- Python 3.7+
- A Windows Hello-compatible device (fingerprint reader, camera for face recognition, or PIN)

## Installation

### From PyPI (Recommended)

Install the latest stable version from PyPI:

```bash
pip install winhello-crypto
```

This provides the `aws-hello-creds` and `winhello-crypto` console scripts.

### From Source

1. Clone the repository:

```bash
git clone https://github.com/SergeDubovsky/WinHello-Crypto.git
cd WinHello-Crypto
```

1. Install required dependencies:

```bash
# Install from requirements.txt (recommended)
pip install -r requirements.txt

# Or install core dependencies only
pip install cryptography pywinrt
```

**Note**: `pywinrt` is only available on Windows and provides Windows Hello integration.

## AWS Credentials Management

### Adding AWS Credentials

Store AWS credentials securely with Windows Hello encryption:

```bash
# Add long-term credentials
aws-hello-creds add-profile my-profile \
    --access-key AKIA1234567890EXAMPLE \
    --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
    --region us-east-1

# Add temporary credentials (with session token)
aws-hello-creds add-profile temp-profile \
    --access-key AKIA1234567890EXAMPLE \
    --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
    --session-token IQoJb3JpZ2luX2VjEHoaCXVzLWVhc3QtMSJIMEYCIQD... \
    --region us-west-2
```

### Using with AWS CLI

#### Method 1: Using AWS CLI profiles (Recommended for single commands)

After adding a profile, it's automatically configured in `~/.aws/config` with a `credential_process` entry:

```ini
[profile my-profile]
credential_process = aws-hello-creds get-credentials --profile my-profile
region = us-east-1
output = json
```

Then use normally with AWS CLI:

```bash
# List S3 buckets using the secure profile
aws s3 ls --profile my-profile

# Deploy CloudFormation stack
aws cloudformation deploy --profile my-profile --template-file template.yaml --stack-name my-stack
```

#### Method 2: Environment Variables (Recommended for multiple commands)

For scenarios where you need to run multiple AWS CLI commands in a session, use the `set-env` command to avoid repeated Windows Hello prompts:

```powershell
# PowerShell - Set environment variables with automatic shell detection
aws-hello-creds set-env my-profile | Invoke-Expression

# Now run multiple commands without additional authentication
aws s3 ls
aws ec2 describe-instances
aws lambda list-functions
```

```cmd
REM Command Prompt - Set environment variables
for /f "delims=" %i in ('aws-hello-creds set-env my-profile') do %i

REM Now run multiple commands
aws s3 ls
aws ec2 describe-instances
```

```bash
# Bash/WSL - Set environment variables
eval "$(aws-hello-creds set-env my-profile)"

# Now run multiple commands
aws s3 ls
aws ec2 describe-instances
```

The tool automatically detects your shell type (PowerShell, CMD, Bash) and outputs the appropriate syntax for setting environment variables.

### Managing Profiles

```bash
# List all encrypted profiles
aws-hello-creds list-profiles

# Remove a profile
aws-hello-creds remove-profile old-profile

# Test credential retrieval (outputs JSON for credential_process)
aws-hello-creds get-credentials --profile my-profile

# Export profile credentials in plain text format (new in v2.1.7)
aws-hello-creds export-profile my-profile

# Output example:
# aws_access_key_id=AKIA1234567890EXAMPLE
# aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# aws_session_token=IQoJb3JpZ2luX2VjEHoaCXVzLWVhc3QtMSJ...

# Set environment variables for shell session
aws-hello-creds set-env my-profile

# Specify shell type explicitly (auto-detection is usually sufficient)
aws-hello-creds set-env my-profile --shell powershell
aws-hello-creds set-env my-profile --shell cmd
aws-hello-creds set-env my-profile --shell bash
```

### Credential Rotation

WinHello-Crypto includes comprehensive credential rotation capabilities for enhanced security:

#### Check Rotation Status

```bash
# Check if credentials need rotation
aws-hello-creds check-rotation my-profile
```

This command analyzes credential age and provides recommendations:

- **Session tokens**: Warns after 30 minutes (typical expiration: 1-12 hours)
- **Long-term credentials**: Warns after 90 days (security best practice)

#### Rotate Credentials

```bash
# Auto-rotate (automatically detects credential type)
aws-hello-creds rotate-credentials my-profile

# Manual rotation with new credentials
aws-hello-creds rotate-credentials my-profile --type manual \
  --access-key AKIA1234567890EXAMPLE \
  --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Rotate temporary credentials
aws-hello-creds rotate-credentials my-profile --type manual \
  --access-key AKIA... --secret-key SECRET... --session-token TOKEN...
```

**Rotation Types:**

- `auto`: Automatically detects whether credentials are temporary or long-term
- `manual`: Use provided new credentials immediately
- `temporary`: Guidance for rotating session tokens
- `access-key`: Guidance for rotating long-term access keys

#### Backup Management

All credential rotations automatically create backups before making changes:

```bash
# List all available backups
aws-hello-creds list-backups

# List backups for specific profile
aws-hello-creds list-backups --profile my-profile

# Restore from backup (format: YYYYMMDD_HHMMSS)
aws-hello-creds restore-backup my-profile 20250806_143000
```

**Security Features:**

- **Encrypted Backups**: All backups use the same Windows Hello encryption
- **Timestamped**: Each backup includes creation timestamp and metadata
- **Rollback Support**: Easy restoration from any backup point
- **Audit Trail**: All rotation activities are logged for compliance

### Windows Batch Integration

Use the batch file for quick access:

```cmd
REM Add credentials
aws-creds.bat add-profile my-aws --access-key AKIA... --secret-key xyz... --region us-east-1

REM List profiles
aws-creds.bat list-profiles
```

## Usage

### File Encryption

### Command Line Interface

The tool provides a simple command-line interface for encrypting and decrypting files:

#### Encrypt a file

```bash
python hello_crypto.py encrypt input.txt encrypted.bin
```

#### Decrypt a file

```bash
python hello_crypto.py decrypt encrypted.bin decrypted.txt
```

### Examples

```bash
# Encrypt a document
python hello_crypto.py encrypt document.pdf document.pdf.enc

# Encrypt a folder (compress first)
tar -czf backup.tar.gz important_folder/
python hello_crypto.py encrypt backup.tar.gz backup.tar.gz.enc

# Decrypt files
python hello_crypto.py decrypt document.pdf.enc document.pdf
python hello_crypto.py decrypt backup.tar.gz.enc backup.tar.gz
```

## How It Works

### Core Security Architecture

1. **Key Derivation**: The application creates a unique key pair in Windows Hello's secure storage
1. **Biometric Challenge**: When encrypting/decrypting, Windows Hello prompts for biometric authentication
1. **Signature Generation**: A signature is generated using the biometric authentication
1. **Key Derivation**: The signature is processed with Argon2id to create a 256-bit AES key
1. **Encryption**: Files are encrypted using AES-256-GCM providing confidentiality and integrity

### Windows Hello Dialog Enhancement

The tool includes advanced window management to provide a seamless authentication experience:

- **Automatic Dialog Detection**: Continuously monitors for Windows Hello authentication dialogs
- **Smart Window Activation**: Automatically brings the dialog to the foreground and activates it
- **Biometric Sensor Triggering**: Simulates user interaction to activate the biometric sensor automatically
- **Cross-Platform Compatibility**: Works across different Windows Hello implementations

This means you'll experience truly hands-free biometric authentication - just provide your fingerprint, face, or PIN when prompted without needing to manually click or focus the dialog window.

## Security Features

- **Hardware-Backed Security**: Keys are stored in Windows Hello's secure storage
- **Biometric Authentication**: Each operation requires biometric verification
- **No Key Storage**: Encryption keys are derived on-demand and cleared from memory
- **Strong Encryption**: AES-256-GCM with authenticated encryption and integrity protection
- **Memory Safety**: Sensitive data is securely cleared from memory after use

## Error Handling

The application includes comprehensive error handling for:

- Windows Hello availability and support
- Biometric authentication failures
- File I/O operations
- Encryption/decryption errors
- Invalid input validation

## API Reference

### FileEncryptor Class

The main class that handles all encryption operations:

```python
from hello_crypto import FileEncryptor

encryptor = FileEncryptor()

# Check Windows Hello support
is_supported = await encryptor.is_supported()

# Encrypt a file
await encryptor.encrypt_file("input.txt", "output.enc")

# Decrypt a file
await encryptor.decrypt_file("input.enc", "output.txt")
```

### Methods

- `is_supported()`: Check if Windows Hello is available
- `ensure_key_exists()`: Create Windows Hello key pair if needed
- `derive_key_from_signature()`: Derive encryption key from biometric signature
- `encrypt_file(input_path, output_path)`: Encrypt a file
- `decrypt_file(input_path, output_path)`: Decrypt a file
- `encrypt_data(data, key)`: Encrypt raw bytes
- `decrypt_data(data, key)`: Decrypt raw bytes

## Troubleshooting

### Common Issues

1. **"Windows Hello is not supported"**
   - Ensure Windows Hello is set up in Windows Settings
   - Verify your device has biometric hardware
   - Check that Windows Hello is enabled for your account

1. **"Biometric authentication failed"**
   - Try using a different biometric method (PIN, fingerprint, face)
   - Ensure your biometric data is properly enrolled
   - Check Windows Hello settings

1. **"Failed to create key"**
   - Run the application as an administrator
   - Ensure Windows Hello service is running
   - Check Windows event logs for detailed error information

1. **Windows Hello dialog doesn't respond to biometric input**
   - The tool now automatically activates the dialog - just wait a moment for it to become responsive
   - If the issue persists, try using Windows Hello PIN as an alternative
   - Check that Windows Hello services are running properly

1. **Environment variables not set properly**
   - Ensure you're using the correct syntax for your shell:
     - PowerShell: `aws-hello-creds set-env profile | Invoke-Expression`
     - CMD: `for /f "delims=" %i in ('aws-hello-creds set-env profile') do %i`
     - Bash: `eval "$(aws-hello-creds set-env profile)"`
   - The tool auto-detects your shell, but you can specify it explicitly with `--shell`

1. **Shell auto-detection issues**
   - Verify your shell type with `--shell powershell`, `--shell cmd`, or `--shell bash`
   - The tool detects shells based on parent process information

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Security Considerations

### General Security

- This tool is designed for personal use and file protection
- The security depends on the integrity of Windows Hello and the underlying hardware
- Always keep backups of important files before encryption
- Test the decryption process before relying on encrypted files
- Consider the implications of hardware failure or Windows reinstallation

### AWS Credentials Security

- **Hardware-Backed Storage**: AWS credentials are encrypted using keys derived from Windows Hello
- **No Plaintext Storage**: Credentials are never stored in plaintext on disk
- **Biometric Gating**: Each credential access requires biometric authentication
- **Isolated Storage**: Credentials are stored separately from AWS config files
- **Key Rotation**: Easily update credentials without changing configuration
- **Session Support**: Supports both long-term and temporary (STS) credentials

### Best Practices

- Regularly rotate your AWS access keys
- Use temporary credentials (STS) when possible
- Monitor AWS CloudTrail for unexpected API calls
- Test credential retrieval regularly to ensure Windows Hello is working
- Keep the Python environment and dependencies updated

## Acknowledgments

- Built using Python's `cryptography` library for secure encryption
- Utilizes Windows Runtime APIs for Windows Hello integration
- Inspired by the need for convenient, hardware-backed file encryption
