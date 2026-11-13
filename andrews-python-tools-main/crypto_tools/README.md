# Crypto Analyzer

Python 3.10+ tools for authenticated encryption, educational ciphers, ciphertext analysis, and PNG steganography. Run the existing script from the repository root; no launcher is required.

## Installation

Classical ciphers, encodings, analysis, and password generation use the standard library. Optional features require:

```console
python -m pip install cryptography
python -m pip install Pillow
```

NumPy is no longer required. Development verification used cryptography 45.0.5 and Pillow 11.1.0; dependencies are optional and missing features return installation guidance.

## Start here

```console
python crypto_tools/crypto_analyzer.py
python crypto_tools/crypto_analyzer.py --help
python crypto_tools/crypto_analyzer.py encrypt caesar "Hello World" 3
python crypto_tools/crypto_analyzer.py decrypt base64 "SGVsbG8gV29ybGQ="
python crypto_tools/crypto_analyzer.py analyze "SGVsbG8=" --json
python crypto_tools/crypto_analyzer.py brute "Khoor Zruog" --report caesar_report.json
```

No arguments starts an interactive prompt. The same commands and options work there, without the Python/script prefix. Use `help`, `<command> --help`, or `quit`. Quoted text and paths with spaces work; Windows backslashes are preserved. EOF and Ctrl+C close the prompt cleanly. CLI Ctrl+C exits with status 130.

## Authenticated encryption

- `aes`: AES-256-GCM with a fresh 16-byte salt and 12-byte nonce per encryption, a 32-byte key derived with PBKDF2-HMAC-SHA256 (600,000 iterations), and an authenticated version/settings header. Wrong passwords and modified ciphertext fail authentication.
- `fernet`: standard Fernet keys and tokens, with authentication supplied by the cryptography library. No extra Base64 wrapping is added.

These implementations use [cryptography's AESGCM API](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM) and [Fernet API](https://cryptography.io/en/latest/fernet/). This project is not an independently audited cryptographic product.

For AES, the CLI prompts for a password using hidden input on a terminal. Encryption asks for confirmation. For automation, supply a UTF-8 key/password file with `--key-file`; only trailing CR/LF characters are stripped. Fernet encryption generates a key when none is supplied. Decryption always needs the original secret.

```console
python crypto_tools/crypto_analyzer.py encrypt aes "Private note"
python crypto_tools/crypto_analyzer.py encrypt fernet "Private note"
python crypto_tools/crypto_analyzer.py decrypt fernet "TOKEN" --key-file fernet.key
python crypto_tools/crypto_analyzer.py file-encrypt crypto_tools/sample_document.txt aes
python crypto_tools/crypto_analyzer.py file-decrypt crypto_tools/sample_document.txt.encrypted --output recovered.txt
```

**Save generated keys separately.** Results intentionally include generated or supplied keys/passwords to preserve the result API. Terminal captures, `--json`, and `--report` can therefore contain secrets and plaintext. Treat them as sensitive and never store a result report beside ciphertext as if it were a safe encrypted artifact. Prefer hidden prompts or `--key-file` over positional secrets, which can appear in shell history or process arguments.

## File operations

Files are binary-safe. Only `aes` and `fernet` are allowed for file encryption. Default encrypted output is `<input>.encrypted`; default recovered output is `<encrypted-input>.decrypted`. Relative paths resolve from the current working directory, including the project root in these examples.

New encrypted files contain only:

```json
{
  "version": 2,
  "cipher_type": "aes",
  "encrypted_content": "BASE64_PAYLOAD"
}
```

No key, password, or original filename is stored. The outer JSON is a routing envelope; its fields are not a separate authenticated metadata format. Authentication is checked by the selected cipher. Decryption never uses an embedded key or filename to choose an output path.

Outputs and reports are created exclusively: existing files and destination symlinks are not overwritten. Parent traversal (`..`) is rejected for output paths; explicit absolute destinations are allowed. Parent directories must already exist. New files request owner-only permissions on POSIX; Windows access remains governed by directory ACLs. This is a local user-directed tool, not a filesystem sandbox.

File encryption is limited to 16 MiB of original data; text input and encrypted/image input reads are limited to 32 MiB. Operations are in memory, not streaming. The original input is never deleted. A failed disk write can leave a partial new output, which must be removed or given a new name before retrying.

## Educational modes

| Mode | Key | Behavior |
| --- | --- | --- |
| caesar | Integer, default 3 | Shift ASCII letters; preserve other Unicode characters. |
| vigenere | ASCII letters | Advance key only for ASCII letters; preserve punctuation and Unicode. |
| atbash / rot13 | None | Fixed ASCII transformations. |
| substitution | 26-letter permutation | Generates a mapping for encryption if omitted; decryption requires the original mapping/alphabet. |
| base64 / hex / binary | None | UTF-8 byte encodings; binary uses space-separated 8-bit groups. |
| xor | Nonempty text | Repeating-key XOR over UTF-8 bytes; ciphertext transported as Base64. |
| morse | None | Uppercase A-Z, digits, spaces; reject unsupported symbols. |

These modes are not secure encryption. Base64, hex, and binary are encodings. Morse decoding is uppercase and does not recover original case. Strict decoders report invalid data rather than silently dropping it.

```console
python crypto_tools/crypto_analyzer.py encrypt vigenere "ATTACKATDAWN" LEMON
python crypto_tools/crypto_analyzer.py generate-key substitution
python crypto_tools/crypto_analyzer.py generate-password 24
```

Password generation uses `secrets`, accepts lengths 8–1024, and draws uniformly from the selected character pool. It does not guarantee that every character class appears.

## Steganography

```console
python crypto_tools/crypto_analyzer.py hide-text cover.png "Hidden message" --output hidden.png
python crypto_tools/crypto_analyzer.py extract-text hidden.png
```

Requires Pillow only. Images are converted to RGB, so transparency and metadata are not preserved. Output must be PNG; JPEG recompression would destroy LSB data. The version-2 payload stores a magic identifier, UTF-8 byte length, SHA-256 checksum, and message. Capacity is `floor(width * height * 3 / 8) - 41` bytes. Images are limited to 16 megapixels and 32 MiB compressed input.

The checksum detects accidental damage, not malicious modification. Steganography is detectable and provides neither encryption nor authentication. Encrypt a message first when confidentiality matters. Tests generate temporary image fixtures; no external image downloads are needed.

## Analysis, output, and status

`analyze` reports character counts, UTF-8 size, sample byte entropy, and compatible encodings. These are clues, not reliable cipher identification or encryption-strength scores. `brute` includes all 26 Caesar shifts ranked by a 0–10 English-readability heuristic.

All operation commands accept `--json` and `--report PATH`. JSON output is a single document without banners. Text output uses a colored result heading on terminals; redirected output stays plain and `NO_COLOR` disables color. Reports are opt-in. If report writing fails after an operation completes, the result (including any generated key) is still printed with `report_error` and CLI status 2.

- `0`: Success.
- `1`: Operation rejected or failed, with an `error` field.
- `2`: CLI argument, secret-input, filesystem/report, or other handled execution error.
- `130`: Interrupted CLI operation.

## Compatibility and migration

The public `CryptoTool` methods remain: `Encrypt`, `Decrypt`, `EncFile`, `DecFile`, `HideText`, `ExtractText`, `GenPassword`, `GenKey`, `Analyze`, `BruteForce`, `ShowResults`, and `ShowHelp`. They retain dictionary results and existing positional parameters. Private algorithm helpers were consolidated. New `legacy=True` options are available on decryption calls. The tool no longer prints progress from analysis methods.

Changes requiring attention:

- New AES output is versioned AES-GCM. Old CBC output requires `decrypt aes TOKEN --legacy` or `Decrypt( token, 'aes', password, legacy=True )`. Legacy CBC cannot detect deliberate alteration; only recover data from trusted sources. The old Unicode/padding bug may have made some historical data unrecoverable.
- Double-Base64 legacy Fernet keys/tokens remain readable; new encryption emits standard keys/tokens.
- Old encrypted JSON files require `file-decrypt PATH --legacy` and an externally supplied key/password. Embedded keys are ignored. Re-encrypt recovered files into the new format.
- XOR now transports UTF-8 byte ciphertext in Base64; old raw-character XOR output is not compatible. Binary now represents UTF-8 bytes rather than Unicode code points.
- Old sentinel-based steganography images require the original tool for recovery; this version reads the length-prefixed version-2 format only.
- Relative file paths now resolve from your working directory, not automatically from `crypto_tools/`.
- Files are never overwritten automatically. File encryption no longer permits educational ciphers. The former README's batch-processing claim was removed because no batch command existed.

## Tests and samples

`sample_document.txt` and `sample_secret.json` are synthetic demonstration inputs, not real credentials. Use only data you own or are authorized to inspect.

```console
python -B -m unittest discover -s crypto_tools -p "test_*.py" -v
```

Tests cover known vectors, Unicode round trips, wrong keys/tampering, standard and legacy formats, binary files, no embedded keys, malicious metadata, overwrite protection, bounds, image capacity/checksums, missing dependencies, parsing, and CLI output.
