# Crypto Tools - Encryption/Decryption Analyzer

## Overview
A comprehensive cryptographic tool supporting multiple ciphers, file encryption, and steganography features.

## Features

### Classical Ciphers
- **Caesar Cipher** - Simple shift cipher with configurable shift value
- **Vigenère Cipher** - Polyalphabetic substitution cipher with keyword
- **Atbash Cipher** - Monoalphabetic substitution (A↔Z, B↔Y, etc.)
- **ROT13** - Special case of Caesar cipher with 13-position shift
- **Substitution Cipher** - Custom alphabet replacement

### Modern Encoding
- **Base64** - Standard base64 encoding/decoding
- **Hexadecimal** - Hex encoding/decoding
- **Binary** - Binary representation encoding/decoding
- **XOR Cipher** - Bitwise XOR with custom key

### Advanced Encryption (requires cryptography library)
- **Fernet** - Symmetric encryption with built-in authentication
- **AES-256-CBC** - Advanced Encryption Standard with password-based key derivation

### Communication Ciphers
- **Morse Code** - International Morse code encoding/decoding

### Analysis Tools
- **Brute Force** - Attempt all Caesar cipher shifts with readability scoring
- **Cipher Detection** - Analyze ciphertext and suggest possible cipher types
- **Text Analysis** - Character frequency and pattern analysis

### File Operations
- **File Encryption** - Encrypt any file type with various ciphers
- **File Decryption** - Decrypt previously encrypted files
- **Batch Processing** - Handle multiple files at once

### Steganography (requires Pillow and numpy)
- **Hide Text in Images** - LSB steganography to hide text in image pixels
- **Extract Hidden Text** - Recover hidden text from steganographic images

### Security Tools
- **Secure Password Generator** - Cryptographically secure password generation
- **Key Generation** - Generate appropriate keys for different cipher types

## Installation

### Basic Installation
```bash
# Clone repository (if not already done)
git clone https://github.com/AndrewPDev/andrews-python-tools.git
cd andrews-python-tools/crypto_tools

# Run the crypto analyzer (basic ciphers only)
python crypto_analyzer.py
```

### Full Installation (with advanced features)
```bash
# Install optional dependencies for advanced features
pip install cryptography      # For Fernet and AES encryption
pip install Pillow numpy      # For steganography features

# Run with all features
python crypto_analyzer.py
```

## Usage Examples

### Interactive Mode
```bash
python crypto_analyzer.py
crypto-analyzer> help
```

### Basic Encryption/Decryption
```bash
# Caesar cipher
crypto-analyzer> encrypt caesar "Hello World" 3
crypto-analyzer> decrypt caesar "Khoor Zruog" 3

# Vigenère cipher
crypto-analyzer> encrypt vigenere "Secret Message" "KEY"
crypto-analyzer> decrypt vigenere "Wixvix Qiwweoi" "KEY"

# Base64 encoding
crypto-analyzer> encrypt base64 "Hello World"
crypto-analyzer> decrypt base64 "SGVsbG8gV29ybGQ="
```

### Advanced Encryption (with cryptography library)
```bash
# Fernet encryption (generates secure key)
crypto-analyzer> encrypt fernet "Sensitive data"

# AES encryption with password
crypto-analyzer> encrypt aes "Top secret info" "mypassword123"
```

### Cryptanalysis
```bash
# Brute force Caesar cipher
crypto-analyzer> brute "Khoor Zruog"

# Analyze unknown ciphertext
crypto-analyzer> analyze "SGVsbG8gV29ybGQ="
```

### File Operations
```bash
# Encrypt a file
crypto-analyzer> file-encrypt sample_document.txt fernet

# Decrypt a file
crypto-analyzer> file-decrypt sample_document.txt.encrypted
```

### Steganography (with Pillow/numpy)
```bash
# Hide text in image
crypto-analyzer> hide-text sample_image.png "Hidden message"

# Extract hidden text
crypto-analyzer> extract-text sample_image_stego.png
```

### Utility Commands
```bash
# Generate secure password
crypto-analyzer> generate-password 20

# Generate cipher key
crypto-analyzer> generate-key vigenere
```

## Data Formats

### Sample Files Included
- `sample_secret.json` - JSON file with sensitive data for testing
- `sample_document.txt` - Text document for file encryption testing

### Encrypted File Format
Encrypted files are saved as JSON with metadata:
```json
{
  "original_file": "document.txt",
  "cipher_type": "fernet",
  "key": "encryption_key_here",
  "encrypted_content": "encrypted_data_here",
  "timestamp": "2025-01-09T10:30:00"
}
```

## Supported Cipher Types

| Cipher | Key Required | Description |
|--------|--------------|-------------|
| caesar | Number (shift) | Simple character shift |
| vigenere | Text keyword | Polyalphabetic substitution |
| atbash | None | Fixed alphabet reversal |
| rot13 | None | 13-position Caesar cipher |
| base64 | None | Standard encoding |
| hex | None | Hexadecimal encoding |
| binary | None | Binary representation |
| xor | Text key | Bitwise XOR operation |
| morse | None | International Morse code |
| substitution | Mapping (optional) | Custom alphabet replacement |
| fernet | Key (optional) | Secure symmetric encryption |
| aes | Password | AES-256 with PBKDF2 |

## Security Notes

### Classical Ciphers
- Caesar, Atbash, ROT13 are easily broken and should only be used for educational purposes
- Vigenère and substitution ciphers provide historical interest but are not cryptographically secure

### Modern Ciphers
- Fernet and AES provide strong encryption suitable for protecting sensitive data
- Always use strong, unique passwords for AES encryption
- Keys and passwords should be stored securely and separately from encrypted data

### Steganography
- LSB steganography is detectable by statistical analysis
- Only use for low-security applications or educational purposes
- Consider using encryption before steganography for better security

## Command Reference

### Encryption Commands
- `encrypt <cipher> <text> [key]` - Encrypt plaintext
- `decrypt <cipher> <text> [key]` - Decrypt ciphertext
- `file-encrypt <file> [cipher]` - Encrypt file
- `file-decrypt <file> [password]` - Decrypt file

### Analysis Commands
- `brute <text>` - Brute force Caesar cipher
- `analyze <text>` - Analyze ciphertext patterns

### Steganography Commands
- `hide-text <image> <text>` - Hide text in image
- `extract-text <image>` - Extract hidden text

### Utility Commands
- `generate-key <cipher>` - Generate appropriate key
- `generate-password [length]` - Generate secure password
- `help` - Show command help
- `quit` - Exit program

## Error Handling

The tool includes comprehensive error handling for:
- Invalid cipher types or parameters
- Missing required keys or passwords
- File not found errors
- Invalid input formats
- Library dependency issues

## Educational Value

This tool demonstrates:
- Classical cryptography principles
- Modern symmetric encryption
- Key derivation techniques
- Steganography concepts
- Cryptanalysis methods
- Secure random generation

Perfect for cybersecurity education, programming practice, and understanding encryption concepts.
