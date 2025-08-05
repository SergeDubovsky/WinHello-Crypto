# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in WinHello-Crypto, please report it privately.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainer directly with details
3. Include steps to reproduce the vulnerability
4. Provide your assessment of the impact and severity

### What to Include

- **Type of issue** (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- **Full paths** of source file(s) related to the manifestation of the issue
- **Location** of the affected source code (tag/branch/commit or direct URL)
- **Special configuration** required to reproduce the issue
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact** of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution**: Depends on complexity, typically 30-90 days

## Security Features

### Cryptographic Security

- **AES-256-CBC**: Industry-standard symmetric encryption
- **PBKDF2**: Key derivation with 100,000+ iterations (OWASP recommended)
- **HMAC-SHA256**: Message authentication and integrity verification
- **Cryptographically secure random**: All IVs and salts use `secrets` module

### Access Control

- **Windows Hello Integration**: Hardware-backed biometric authentication
- **Rate Limiting**: Protection against brute force attacks
- **Audit Logging**: Comprehensive security event logging
- **Input Validation**: All inputs validated against security patterns

### Memory Protection

- **Secure Memory Clearing**: Sensitive data cleared from memory using OS-specific APIs
- **Key Lifecycle Management**: Keys derived on-demand and immediately cleared
- **No Persistent Keys**: Encryption keys never stored on disk

### File System Security

- **Path Traversal Protection**: Input sanitization prevents directory traversal
- **File Size Limits**: Protection against DoS attacks via large files
- **Extension Filtering**: Blocked dangerous file extensions
- **Atomic Operations**: Temporary files used for atomic writes

## Security Best Practices for Users

### General Usage

1. **Keep Windows Hello Updated**: Ensure Windows and drivers are current
2. **Use Strong Biometrics**: Configure multiple biometric methods if available
3. **Regular Key Rotation**: Rotate AWS credentials periodically
4. **Monitor Access Logs**: Review security logs regularly
5. **Backup Strategy**: Maintain secure backups before encryption

### AWS Credentials

1. **Use Temporary Credentials**: Prefer STS tokens over long-term keys
2. **Principle of Least Privilege**: Grant minimal required permissions
3. **Monitor CloudTrail**: Watch for unexpected API calls
4. **Secure Network**: Use encrypted connections and VPNs
5. **Multiple Profiles**: Separate credentials by environment/purpose

### System Security

1. **Endpoint Protection**: Use antivirus and endpoint detection
2. **System Updates**: Keep Windows and security patches current
3. **Network Security**: Use firewalls and network monitoring
4. **Physical Security**: Secure physical access to devices
5. **User Education**: Train users on security best practices

## Known Limitations

### Security Limitations

- **Hardware Dependency**: Security relies on Windows Hello hardware integrity
- **Local Access**: Physical access to unlocked system may bypass protections
- **Memory Dumps**: Advanced attackers with system access might extract keys from memory
- **Side Channel Attacks**: Theoretical timing attacks on cryptographic operations

### Platform Limitations

- **Windows Only**: Requires Windows 10/11 with Windows Hello
- **Hardware Requirements**: Needs compatible biometric hardware
- **User Account**: Requires Windows Hello setup for current user
- **Admin Rights**: Some operations may require elevated privileges

## Vulnerability Disclosure

We follow responsible disclosure practices:

1. **Private Notification**: Security researchers contact us privately
2. **Acknowledgment**: We acknowledge receipt within 48 hours
3. **Investigation**: We investigate and develop fixes
4. **Coordination**: We coordinate disclosure timeline with researcher
5. **Public Disclosure**: Security advisory published after fix deployment
6. **Recognition**: Security researchers credited in advisories (if desired)

## Security Updates

Security updates are released as soon as possible after verification:

- **Critical**: Within 24-48 hours
- **High**: Within 1 week
- **Medium**: Within 1 month
- **Low**: With next regular release

Users are strongly encouraged to:
- Subscribe to security notifications
- Update promptly when security releases are available
- Test updates in non-production environments first

## Contact Information

For security-related inquiries:
- **Security Issues**: Use private reporting methods only
- **General Questions**: Open GitHub issues for non-security topics
- **Documentation**: Contribute improvements via pull requests

## Compliance and Standards

This project follows:
- **OWASP Cryptographic Storage Cheat Sheet**
- **NIST Cybersecurity Framework**
- **Microsoft Security Development Lifecycle (SDL)**
- **SANS Secure Coding Practices**