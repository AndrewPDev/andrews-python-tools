## �🔐 Hash Identifier Tool

**File:** `hash_tester_main.py`

A powerful hash identification tool that analyzes hash strings and identifies the most likely hash algorithm based on pattern matching and characteristic analysis.

### Features
- Supports 15+ hash types including MD5, SHA variants, bcrypt, scrypt, Argon2, PBKDF2
- Single hash analysis with confidence scoring
- Batch file processing for multiple hashes
- Character set analysis and security recommendations
- Interactive command-line interface

### Supported Hash Types
- **Cryptographic Hashes:** MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- **Password Hashing:** bcrypt, scrypt, Argon2, PBKDF2
- **Windows Hashes:** NTLM, LM Hash
- **Application-Specific:** MySQL5, WordPress, Drupal 7, Joomla

### Installation & Usage
```bash
# Clone repository (if not already done)
git clone https://github.com/AndrewPDev/andrews-python-tools.git
cd andrews-python-tools

# Run the hash identifier
python hash_tester/hash_tester_main.py
```

### Usage Examples
#### Single Hash Analysis
```
Enter hash to identify (or command): 5d41402abc4b2a76b9719d911017c592
```

#### Batch File Analysis
```
Enter hash to identify (or command): file:sample_hashes.txt
```

#### Sample Hash File Format
Create a text file with one hash per line:
```
# Sample hash file - comments start with #
5d41402abc4b2a76b9719d911017c592
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
*23AE809DDACAF96AF0FD78ED04B6A265E05AA257
```

### Output Example
```
============================================================
Hash Analysis for: 5d41402abc4b2a76b9719d911017c592
============================================================

Found 3 possible match(es):

1. MD5 - MD5 (Message Digest 5)
   Confidence: 80%
   Example: 5d41402abc4b2a76b9719d911017c592

2. NTLM - NTLM Hash
   Confidence: 50%
   Example: b4b9b02e6f09a9bd760f388b67351e2b

3. LM - LM Hash (LAN Manager)
   Confidence: 50%
   Example: aad3b435b51404eeaad3b435b51404ee

Additional Analysis:
   Length: 32 characters
   Character set: Hexadecimal (0-9, a-f)
   Most likely: MD5 (80%)
   WARNING: This appears to be a weak hash algorithm!
```

### Commands
| Command | Description |
|---------|-------------|
| `help` | Display usage information |
| `quit`, `exit`, `q` | Exit the program |
| `file:filename.txt` | Analyze multiple hashes from file |

### Security Notes
- **MD5 and SHA-1** are considered cryptographically weak and should not be used for security purposes
- **bcrypt, scrypt, Argon2** are recommended for password hashing
- This tool is for **authorized testing only** - ensure proper permissions before use
- Always verify hash identification results with additional testing