# WinHello-Crypto

[![CI](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/ci.yml)
[![Security Tests](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/security-tests.yml/badge.svg)](https://github.com/SergeDubovsky/WinHello-Crypto/actions/workflows/security-tests.yml)
[![codecov](https://codecov.io/gh/SergeDubovsky/WinHello-Crypto/branch/main/graph/badge.svg)](https://codecov.io/gh/SergeDubovsky/WinHello-Crypto)
[![PyPI version](https://badge.fury.io/py/winhello-crypto.svg)](https://badge.fury.io/py/winhello-crypto)
[![Python Support](https://img.shields.io/pypi/pyversions/winhello-crypto.svg)](https://pypi.org/project/winhello-crypto/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Secure AWS credential storage and file encryption using Windows Hello biometric authentication.

## Quick start

### Install

```bash
pip install winhello-crypto
```

### AWS Credentials Manager

```bash
# Store credentials
aws-hello-creds set <profile> --access-key <key> --secret-key <secret> [--session-token <token>] [--region <region>"

# Retrieve credentials
aws-hello-creds get <profile> --format credential-process|json|ini

# List profiles
aws-hello-creds list [--format table|json]

# Export to environment variables
aws-hello-creds export <profile> --shell powershell|cmd|bash

# Delete credentials
aws-hello-creds delete <profile>
```

### File encryption

```bash
# Encrypt (default output: <input>.enc)
winhello-crypto encrypt <input-file> [-o <output-file>"

# Decrypt (default output: strip .enc or add .dec)
winhello-crypto decrypt <input-file> [-o <output-file>"

# Verify integrity of an encrypted file
winhello-crypto verify <encrypted-file>
```

## AWS Credentials Manager commands

### Basic operations

```bash
aws-hello-creds set <profile> --access-key <key> --secret-key <secret> [--session-token <token>] [--region <region>]
aws-hello-creds get <profile> --format credential-process|json|ini
aws-hello-creds list [--format table|json]
aws-hello-creds export <profile> --shell powershell|cmd|bash
aws-hello-creds delete <profile>
```

### Advanced operations

```bash
# Check if rotation is recommended
aws-hello-creds rotate --check <profile>

# Rotate credentials
aws-hello-creds rotate <profile> [--type auto|manual|temporary|access-key] \
  [--access-key <key>] [--secret-key <secret>] [--session-token <token>]

# Backups of stored profiles
aws-hello-creds backup list [--profile <profile>]
aws-hello-creds backup restore <profile> <YYYYMMDD_HHMMSS>

# Manage ~/.aws/config profiles (encrypt/decrypt)
aws-hello-creds profile encrypt <name> [--output <file>] [--delete-plain]
aws-hello-creds profile decrypt <file> [--profile <name>]
```

## File encryption commands

```bash
winhello-crypto encrypt <input-file> [-o <output-file>]
winhello-crypto decrypt <input-file> [-o <output-file>]
winhello-crypto verify <encrypted-file>
```

## Security features

- Windows Hello integration (biometric/PIN)
- AES-256-GCM encryption, integrity-checked
- No plaintext at rest; atomic writes
- Argon2id key derivation
- Basic rate limiting and audit logging

## Requirements

- Windows 10/11 with Windows Hello enabled
- Python 3.7+

## Troubleshooting

- Windows Hello not available: enable via Settings > Accounts > Sign-in options
- Authentication failed: ensure biometric/PIN is set up and unlocked
- Profile not found: use `aws-hello-creds list` to view existing profiles
- Permission denied to Credential Manager: try running the shell as Administrator

## Development

```bash
# Install dev deps
pip install -e ".[dev]"

# Run tests
pytest

# Security checks (optional)
bandit -r .
safety check

# Format
black .
```

## License

Apache License 2.0 - see [LICENSE](LICENSE).
