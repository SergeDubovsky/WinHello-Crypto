# WinHello-Crypto PyPI Deployment

## Overview

WinHello-Crypto is now officially available on the Python Package Index (PyPI), making it easy for users worldwide to install and use with a simple `pip install` command.

## 🎉 Current Status: LIVE on PyPI

- **Package URL**: [https://pypi.org/project/winhello-crypto/](https://pypi.org/project/winhello-crypto/)
- **Version**: 2.0.0
- **Published**: August 6, 2025
- **Console Scripts**: `aws-hello-creds` and `winhello-crypto`

## Installation for Users

Users can now install WinHello-Crypto with a single command:

```bash
pip install winhello-crypto
```

### Available Commands After Installation

#### AWS Credential Management

```bash
# Add encrypted credentials
aws-hello-creds add-profile work --access-key AKIA... --secret-key ...

# List all profiles
aws-hello-creds list-profiles

# Set environment variables
aws-hello-creds set-env work

# Get credentials for AWS CLI
aws-hello-creds get-credentials --profile work
```

#### File Encryption

```bash
# Encrypt a file
winhello-crypto encrypt document.txt encrypted.bin

# Decrypt a file
winhello-crypto decrypt encrypted.bin decrypted.txt
```

## Development and Maintenance

### For Future Updates

To publish a new version:

1. **Update version** in `pyproject.toml`
2. **Build package**: `python -m build`
3. **Upload to PyPI**: `python -m twine upload dist/*`

### Package Structure

The PyPI package includes:

- Core modules: `hello_crypto.py`, `aws_hello_creds.py`, `security_utils.py`, `security_config.py`
- Console scripts: Automatically installed and available in PATH
- Dependencies: Automatically resolved for Windows platforms
- Documentation: README, CHANGELOG, and LICENSE included

## Benefits

- ✅ **Simple installation**: One-command pip install
- ✅ **Global availability**: Accessible to Python developers worldwide
- ✅ **Automatic dependency resolution**: Windows-specific packages handled correctly
- ✅ **Professional credibility**: Listed on official Python Package Index
- ✅ **Version management**: Easy updates with `pip install --upgrade winhello-crypto`
- ✅ **Virtual environment support**: Works in any Python environment
- ✅ **Console scripts**: Direct CLI access without Python module syntax

## Requirements

- Python 3.7+
- Windows 10/11 with Windows Hello enabled
- Biometric sensor or PIN/password authentication setup

## Technical Details

### Dependencies Managed

- `cryptography>=45.0.6,<46.0.0` - Core encryption library
- `winrt-runtime>=3.2.0,<4.0.0` - Windows Runtime support
- `winrt-Windows.Security.Credentials>=3.2.0,<4.0.0` - Windows Hello integration
- `winrt-Windows.Storage.Streams>=3.2.0,<4.0.0` - Secure data handling

### Platform Support

- **Primary**: Windows 10/11 (with Windows Hello)
- **Dependencies**: Platform-specific packages automatically excluded on non-Windows systems
