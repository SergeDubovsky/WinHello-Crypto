# WinHello-Crypto

A secure file encryption tool that uses Windows Hello biometric authentication to derive encryption keys. This application provides hardware-backed security by leveraging Windows Hello's biometric authentication (fingerprint, face, or PIN) to encrypt and decrypt files using AES-256-CBC encryption.

## Features

- 🔐 **Biometric Authentication**: Uses Windows Hello for secure key derivation
- 🛡️ **Strong Encryption**: AES-256-CBC with PKCS7 padding
- 🔑 **Hardware-Backed Security**: Encryption keys derived from Windows Hello signatures
- 🧹 **Memory Safety**: Secure memory clearing of sensitive data
- 📁 **File Operations**: Encrypt and decrypt any file type
- ⚡ **Async Operations**: Non-blocking file operations

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

## Usage

### Command Line Interface

The tool provides a simple command-line interface for encrypting and decrypting files:

#### Encrypt a file

```bash
python Hello-Crypto.py encrypt input.txt encrypted.bin
```

#### Decrypt a file

```bash
python Hello-Crypto.py decrypt encrypted.bin decrypted.txt
```

### Examples

```bash
# Encrypt a document
python Hello-Crypto.py encrypt document.pdf document.pdf.enc

# Encrypt a folder (compress first)
tar -czf backup.tar.gz important_folder/
python Hello-Crypto.py encrypt backup.tar.gz backup.tar.gz.enc

# Decrypt files
python Hello-Crypto.py decrypt document.pdf.enc document.pdf
python Hello-Crypto.py decrypt backup.tar.gz.enc backup.tar.gz
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
from Hello-Crypto import FileEncryptor

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

- This tool is designed for personal use and file protection
- The security depends on the integrity of Windows Hello and the underlying hardware
- Always keep backups of important files before encryption
- Test the decryption process before relying on encrypted files
- Consider the implications of hardware failure or Windows reinstallation

## Acknowledgments

- Built using Python's `cryptography` library for secure encryption
- Utilizes Windows Runtime APIs for Windows Hello integration
- Inspired by the need for convenient, hardware-backed file encryption
