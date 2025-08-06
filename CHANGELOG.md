# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Environment Variable Support**: New `set-env` command to output AWS credentials as environment variables for shell sessions
- **Automatic Shell Detection**: Tool now automatically detects PowerShell, CMD, and Bash shells and formats output accordingly
- **Enhanced Windows Hello UX**: Automatic dialog activation and biometric sensor triggering for seamless authentication
- **Multi-Shell Compatibility**: Full support for PowerShell, Command Prompt, and Bash/WSL environments
- **Advanced Window Management**: Automatic Windows Hello dialog detection, focus, and activation
- **Biometric Sensor Auto-Activation**: Simulated mouse interaction to trigger biometric sensors without manual clicking

### Enhanced
- **User Experience**: Windows Hello dialogs now automatically activate and become responsive without manual intervention
- **CLI Interface**: Improved help documentation with examples for all shell types
- **Error Handling**: Better error messages and troubleshooting guidance for shell and authentication issues
- **Documentation**: Comprehensive README updates with new features and usage patterns

### Technical Improvements
- **Shell Detection Algorithm**: Uses process information and environment variables for accurate shell type detection
- **Window API Integration**: Advanced Windows API calls for reliable dialog management
- **Asynchronous Operations**: Background tasks for dialog monitoring and activation
- **Memory Safety**: Enhanced secure memory clearing for environment variable handling

### Dependencies
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
