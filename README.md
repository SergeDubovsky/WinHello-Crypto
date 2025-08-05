# WinHello-Crypto

[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green.svg)](https://github.com/SergeDubovsky/WinHello-Crypto)
[![Encryption](https://img.shields.io/badge/Encryption-AES%20256%20%2B%20PBKDF2-blue.svg)](https://github.com/SergeDubovsky/WinHello-Crypto)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-lightgrey.svg)](https://github.com/SergeDubovsky/WinHello-Crypto)
[![Python](https://img.shields.io/badge/Python-3.7%2B-yellow.svg)](https://github.com/SergeDubovsky/WinHello-Crypto)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](https://github.com/SergeDubovsky/WinHello-Crypto/blob/main/LICENSE)

**🔐 Enterprise-Grade AWS Credential Security with Windows Hello Biometric Authentication**

A revolutionary approach to AWS credential management that **eliminates plaintext storage vulnerabilities** by leveraging Windows Hello's hardware-backed biometric authentication. This tool transforms credential security from a liability into a robust, user-friendly protection layer.

## 🚨 The Problem We Solve

Traditional AWS credential storage methods expose organizations to significant security risks:
- **Plaintext credentials** in `~/.aws/credentials` files
- **Environment variables** stored in shell profiles  
- **Hardcoded keys** in configuration files
- **Complex certificate management** with potential key exposure
- **Credential theft** from compromised developer machines
- **No audit trail** for credential access

## 💡 Our Solution

WinHello-Crypto provides **hardware-backed credential protection** that:
- ✅ **Eliminates plaintext storage** - Zero credentials stored in readable format
- ✅ **Requires biometric authentication** - Each access needs fingerprint/face/PIN
- ✅ **Provides seamless integration** - Works transparently with existing AWS CLI workflows
- ✅ **Offers enterprise-grade encryption** - AES-256 + PBKDF2 + HMAC integrity protection
- ✅ **Ensures memory safety** - Secure clearing of sensitive data from memory
- ✅ **Maintains audit trails** - Comprehensive logging without credential exposure

## 🛡️ Security Impact & Benefits

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
- **🔥 100% reduction** in plaintext credential exposure
- **🔒 Hardware-backed protection** using TPM/Secure Enclave
- **⚡ Real-time biometric verification** for each access
- **🛡️ OWASP-compliant** secure coding practices
- **📊 Enterprise audit trails** without credential leakage
- **💾 Memory-safe operations** with secure data clearing

## Features

- 🔐 **Biometric Authentication**: Uses Windows Hello for secure key derivation
- 🛡️ **Strong Encryption**: AES-256-CBC with PKCS7 padding
- 🔑 **Hardware-Backed Security**: Encryption keys derived from Windows Hello signatures
- 🧹 **Memory Safety**: Secure memory clearing of sensitive data
- 📁 **File Operations**: Encrypt and decrypt any file type
- ☁️ **AWS Credentials Manager**: Securely store and retrieve AWS credentials
- 🔄 **AWS CLI Integration**: Seamless integration with AWS CLI credential_process
- ⚡ **Async Operations**: Non-blocking file operations

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

1. Clone the repository:

```bash
git clone https://github.com/SergeDubovsky/WinHello-Crypto.git
cd WinHello-Crypto
```

2. Install required dependencies:

```bash
pip install cryptography winrt
```

## AWS Credentials Management

### Adding AWS Credentials

Store AWS credentials securely with Windows Hello encryption:

```bash
# Add long-term credentials
python aws_hello_creds.py add-profile my-profile \
    --access-key AKIA1234567890EXAMPLE \
    --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
    --region us-east-1

# Add temporary credentials (with session token)
python aws_hello_creds.py add-profile temp-profile \
    --access-key AKIA1234567890EXAMPLE \
    --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
    --session-token IQoJb3JpZ2luX2VjEHoaCXVzLWVhc3QtMSJIMEYCIQD... \
    --region us-west-2
```

### Using with AWS CLI

After adding a profile, it's automatically configured in `~/.aws/config` with a `credential_process` entry:

```ini
[profile my-profile]
credential_process = python "C:\Project\WinHello-Crypto\aws_hello_creds.py" get-credentials --profile my-profile
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

### Managing Profiles

```bash
# List all encrypted profiles
python aws_hello_creds.py list-profiles

# Remove a profile
python aws_hello_creds.py remove-profile old-profile

# Test credential retrieval (outputs JSON for credential_process)
python aws_hello_creds.py get-credentials --profile my-profile
```

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

1. **Key Derivation**: The application creates a unique key pair in Windows Hello's secure storage
2. **Biometric Challenge**: When encrypting/decrypting, Windows Hello prompts for biometric authentication
3. **Signature Generation**: A signature is generated using the biometric authentication
4. **Key Derivation**: The signature is hashed with SHA-256 to create a 256-bit AES key
5. **Encryption**: Files are encrypted using AES-256-CBC with a random IV and PKCS7 padding

## Security Features

- **Hardware-Backed Security**: Keys are stored in Windows Hello's secure storage
- **Biometric Authentication**: Each operation requires biometric verification
- **No Key Storage**: Encryption keys are derived on-demand and cleared from memory
- **Strong Encryption**: AES-256-CBC with proper padding and random IVs
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

2. **"Biometric authentication failed"**
   - Try using a different biometric method (PIN, fingerprint, face)
   - Ensure your biometric data is properly enrolled
   - Check Windows Hello settings

3. **"Failed to create key"**
   - Run the application as an administrator
   - Ensure Windows Hello service is running
   - Check Windows event logs for detailed error information

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

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
