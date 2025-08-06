# WinHello-Crypto

[![CI](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/ci.yml)
[![Security Tests](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/security-tests.yml/badge.svg)](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/security-tests.yml)
[![codecov](https://codecov.io/gh/SergeDubovsky/WinHello-Crypto/branch/main/graph/badge.svg)](https://codecov.io/gh/SergeDubovsky/WinHello-Crypto)
[![PyPI version](https://badge.fury.io/py/winhello-crypto.svg)](https://badge.fury.io/py/winhello-crypto)
[![Python Support](https://img.shields.io/pypi/pyversions/winhello-crypto.svg)](https://pypi.org/project/winhello-crypto/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Secure AWS credential storage and file encryption using Windows Hello biometric authentication.

## Quick Start

### Install
```bash
pip install winhello-crypto
```

### AWS Credentials Manager
```bash
# Store AWS credentials
aws-hello-creds set myprofile --access-key AKIA... --secret-key secret123

# Use stored credentials  
aws-hello-creds get myprofile

# List all profiles
aws-hello-creds list

# Export as environment variables
aws-hello-creds export myprofile
```

### File Encryption
```bash
# Encrypt a file
winhello-crypto encrypt myfile.txt

# Decrypt a file
winhello-crypto decrypt myfile.txt.enc
```

## AWS Credentials Manager Commands

### Basic Operations
```bash
# Store credentials
aws-hello-creds set <profile> --access-key <key> --secret-key <secret> [--session-token <token>] [--region <region>]

# Retrieve credentials
aws-hello-creds get <profile> [--format json|env|ini]

# List all profiles
aws-hello-creds list [--format table|json]

# Delete credentials
aws-hello-creds delete <profile>

# Check if profile exists
aws-hello-creds exists <profile>
```

### Advanced Operations
```bash
# Backup all credentials to encrypted file
aws-hello-creds backup --file backup.enc

# Restore credentials from backup
aws-hello-creds restore --file backup.enc

# Rotate credentials (requires AWS CLI configured)
aws-hello-creds rotate <profile>

# Export as environment variables
aws-hello-creds export <profile> [--shell bash|powershell|cmd]

# Copy profile
aws-hello-creds copy <source> <destination>

# Update existing profile
aws-hello-creds update <profile> [--access-key <key>] [--secret-key <secret>] [--session-token <token>] [--region <region>]
```

### File Operations
```bash
# Encrypt file with profile credentials
aws-hello-creds encrypt-file <profile> <input-file> [--output <output-file>]

# Decrypt file with profile credentials
aws-hello-creds decrypt-file <profile> <input-file> [--output <output-file>]
```

## File Encryption Commands

```bash
# Encrypt file
winhello-crypto encrypt <input-file> [--output <output-file>]

# Decrypt file
winhello-crypto decrypt <input-file> [--output <output-file>]

# Verify integrity
winhello-crypto verify <encrypted-file>
```

## Use Cases

### Development Workflows
```bash
# Set up dev environment
aws-hello-creds set dev --access-key AKIA... --secret-key secret123 --region us-west-2
aws-hello-creds export dev --shell powershell

# Switch to production
aws-hello-creds export prod --shell powershell
```

### CI/CD Integration
```bash
# Backup before deployment
aws-hello-creds backup --file pre-deploy-backup.enc

# Restore if needed
aws-hello-creds restore --file pre-deploy-backup.enc
```

### Secure File Sharing
```bash
# Encrypt sensitive files
winhello-crypto encrypt config.json
winhello-crypto encrypt database-backup.sql

# Share encrypted files safely
# Recipients need Windows Hello to decrypt
```

## Security Features

- **Windows Hello Integration**: Uses biometric authentication (fingerprint, face, PIN)
- **AES-256-GCM Encryption**: Military-grade encryption for stored credentials
- **No Plain Text Storage**: All credentials encrypted at rest
- **Secure Key Derivation**: PBKDF2 with high iteration count
- **Memory Protection**: Sensitive data cleared from memory after use

## Requirements

- Windows 10/11 with Windows Hello enabled
- Python 3.7+
- Biometric device (fingerprint reader, camera) or PIN set up

## Troubleshooting

### Windows Hello Not Available
```
Error: Windows Hello is not available on this device
```
**Solution**: Enable Windows Hello in Settings > Accounts > Sign-in options

### Authentication Failed
```
Error: User verification failed
```
**Solution**: 
- Ensure biometric device is working
- Try using PIN if biometric fails
- Check Windows Hello is enabled for apps

### Profile Not Found
```
Error: Profile 'myprofile' not found
```
**Solution**: Use `aws-hello-creds list` to see available profiles

### Permission Denied
```
Error: Access denied to Windows Credential Manager
```
**Solution**: Run as administrator or check Windows Credential Manager permissions

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run security checks
bandit -r .
safety check

# Format code
black .
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
