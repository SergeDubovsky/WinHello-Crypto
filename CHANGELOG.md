# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Credential Rotation System**: Comprehensive credential rotation with automatic backup and rollback capabilities
- **Rotation Monitoring**: Automatic detection of aging credentials with smart recommendations
- **Backup Management**: Encrypted backup storage with timestamped restore points for all credentials
- **Rotation Types**: Support for auto, manual, temporary, and access-key rotation workflows
- **Environment Variable Support**: New `set-env` command to output AWS credentials as environment variables for shell sessions
- **Automatic Shell Detection**: Tool now automatically detects PowerShell, CMD, and Bash shells and formats output accordingly
- **Enhanced Windows Hello UX**: Automatic dialog activation and biometric sensor triggering for seamless authentication
- **Multi-Shell Compatibility**: Full support for PowerShell, Command Prompt, and Bash/WSL environments
- **Advanced Window Management**: Automatic Windows Hello dialog detection, focus, and activation
- **Biometric Sensor Auto-Activation**: Simulated mouse interaction to trigger biometric sensors without manual clicking

### Enhanced
- **Security Framework**: Enhanced credential lifecycle management with automated backup creation
- **CLI Interface**: Added rotation commands (`check-rotation`, `rotate-credentials`, `list-backups`, `restore-backup`)
- **User Experience**: Windows Hello dialogs now automatically activate and become responsive without manual intervention
- **Error Handling**: Better error messages and troubleshooting guidance for shell and authentication issues
- **Documentation**: Comprehensive README updates with new features and usage patterns
- **Audit System**: Extended logging for rotation operations and backup management

### Technical Improvements
- **Backup System**: Encrypted, timestamped backups with metadata for all credential changes
- **Credential Analysis**: Age detection and expiration warnings for both temporary and long-term credentials
- **Shell Detection Algorithm**: Uses process information and environment variables for accurate shell type detection
- **Window API Integration**: Advanced Windows API calls for reliable dialog management
- **Asynchronous Operations**: Background tasks for dialog monitoring and activation
- **Memory Safety**: Enhanced secure memory clearing for environment variable handling and rotation operations

### Dependencies

- **Updated**: `cryptography>=45.0.6,<46.0.0` (security updates and performance improvements)
- **Updated**: `pytest>=8.3.0,<9.0.0` (latest stable testing framework with improved async support)
- **Updated**: `pytest-asyncio>=0.24.0,<1.0.0` (async test improvements and reliability)
- **Updated**: `pytest-cov>=6.0.0,<7.0.0` (enhanced coverage reporting)
- **Updated**: `black>=25.1.0,<26.0.0` (latest code formatting with improved Python 3.13 support)
- **Updated**: `flake8>=7.3.0,<8.0.0` (improved linting capabilities)
- **Updated**: `mypy>=1.17.1,<2.0.0` (enhanced type checking with latest Python support)
- **Updated**: `bandit>=1.8.6,<2.0.0` (security scanning with improved detection)
- **Updated**: `safety>=3.2.0,<3.3.0` (vulnerability scanning)
- **Updated**: `sphinx>=7.0.0,<8.0.0` (documentation generation)
- **Updated**: `sphinx-rtd-theme>=2.0.0,<3.0.0` (documentation theme)
- **Fixed**: WinRT package dependencies - migrated from single `pywinrt` to individual packages
- **Added**: `winrt-runtime>=3.2.0,<4.0.0` for core Windows Runtime support
- **Added**: `winrt-Windows.Security.Credentials>=3.2.0,<4.0.0` for Windows Hello integration
- **Added**: `winrt-Windows.Storage.Streams>=3.2.0,<4.0.0` for secure data handling
- **Added**: `psutil>=5.9.0,<6.0.0` for enhanced shell detection capabilities

## Previous Versions

### Core Features (Existing)

- Windows Hello biometric authentication integration
- AES-256-CBC encryption with PBKDF2 key derivation
- AWS credential management with credential_process integration
- Hardware-backed security using Windows Hello key storage
- Comprehensive security auditing and rate limiting
- File encryption and decryption capabilities
- Memory-safe operations with secure data clearing
