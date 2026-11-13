# Andrew's Python Tools

A collection of Python tools and utilities for various purposes.

## 📋 Overview

This repository contains Python tools and utilities developed for educational and professional use. Currently featuring a hash identification tool for cybersecurity analysis, a CSV/TSV analyzer with explicit cleaning and safe exports, an SEO website analyzer for optimization auditing, a comprehensive crypto analyzer for encryption/decryption operations, a financial data analyzer for investment analysis and portfolio management, a database security auditor for comprehensive database vulnerability assessment, a Digital Conscience Python code reviewer with syntax-aware performance and best-practice recommendations, and an Incident Simulator for chaos engineering and production failure training.

---

## General Information

### Prerequisites
- Digital Conscience (`code_quality`): Python 3.10 or higher.
- Crypto Analyzer (`crypto_tools`): Python 3.10 or higher.
- CSV Analyzer (`csv_main`): Python 3.10 or higher; standard library only.
- Other tools: existing baseline is Python 3.6 or higher; consult their individual READMEs.
- Most basic features use the standard library. Crypto Analyzer optionally uses `cryptography` for authenticated encryption and `Pillow` for image steganography.

### Installation
```bash
git clone https://github.com/AndrewPDev/andrews-python-tools.git
cd andrews-python-tools
```

### Make Scripts Executable (Unix/Linux)
```bash
chmod +x hash_tester/hash_tester_main.py
chmod +x csv_main/csv_analyzer.py
chmod +x seo_tools/seo_analyzer.py
chmod +x code_quality/digital_conscience.py
chmod +x crypto_tools/crypto_analyzer.py
chmod +x database_tools/db_auditor.py
chmod +x financial_tools/financial_analyzer.py
chmod +x incident_tools/incident_simulator.py
```

## 🏗️ Project Structure

```
andrews-python-tools/
├── README.md
├── hash_tester/             # Hash identifier module
|   ├── hash_tester_main.py  # Hash identifier tool
|   └── README.md
├── code_quality/            # Python code review module
│   ├── digital_conscience.py # Syntax-aware reviewer and CLI
│   ├── test_sample.py       # Intentional findings for demonstration
│   ├── test_conscience.py   # Scanner and CLI regression tests
|   └── README.md
├── incident_tools/          # Incident simulation module
│   ├── incident_simulator.py # Production failure scenario simulator for training
|   └── README.md
├── csv_main/                # CSV analyzer module
│   ├── csv_analyzer.py      # CSV/TSV analyzer and cleaner
│   ├── sample_data.csv      # Sample CSV file for testing
|   └── README.md
├── seo_tools/               # SEO analysis module
│   ├── seo_analyzer.py      # SEO website analyzer and auditor
|   └── README.md
├── crypto_tools/            # Cryptographic analysis module
│   ├── crypto_analyzer.py   # Encryption/decryption and crypto analysis tool
│   ├── sample_secret.json   # Sample encrypted data
│   ├── sample_document.txt  # Sample document for encryption
│   └── README.md            # Detailed crypto tool documentation
├── financial_tools/         # Financial analysis module
│   ├── financial_analyzer.py # Investment and portfolio analyzer
│   ├── sample_portfolio.json # Sample portfolio data
│   ├── sample_portfolio.csv  # Sample portfolio CSV data
│   ├── sample_stock.json     # Sample stock analysis data
│   ├── sample_crypto.json    # Sample cryptocurrency data
│   └── README.md            # Financial tools documentation
├── database_tools/          # Database security module
│   ├── db_auditor.py        # Database security auditor and analysis tool
│   ├── sample_database.db   # Sample SQLite database for testing
│   └── README.md            # Database tools documentation
│   └── README.md            # Database security tool documentation
└── examples/
    └── sample_hashes.txt    # Example hash file (optional)
```

## CSV Analyzer and Cleaner

The reworked [CSV Analyzer](csv_main/README.md) supports CSV/TSV text with quoted fields, explicit encodings, conservative type inference, structured quality reports, cleaning previews, and exports that never overwrite existing files. Excel workbooks must first be exported to CSV.

```console
python csv_main/csv_analyzer.py
python csv_main/csv_analyzer.py analyze csv_main/sample_data.csv --json
python csv_main/csv_analyzer.py clean csv_main/sample_data.csv --trim --drop-empty --dedupe --dry-run
python csv_main/csv_analyzer.py clean csv_main/sample_data.csv --trim --drop-empty --dedupe --output cleaned.csv
python -B -m unittest discover -s csv_main -p "test_*.py" -v
```

Requires Python 3.10+, with no external dependencies. Reports include sample data; handle them accordingly. See the tool README for format details, resource limits, interactive commands, and API compatibility.

## Crypto Analyzer

The reworked [Crypto Analyzer](crypto_tools/README.md) provides authenticated AES-GCM and Fernet encryption, binary-safe file operations without embedded decryption keys, educational ciphers, UTF-8 encodings, ciphertext analysis, and lossless PNG steganography. It supports interactive commands, direct CLI use, JSON reports, and overwrite protection.

```console
python crypto_tools/crypto_analyzer.py
python crypto_tools/crypto_analyzer.py encrypt caesar "Hello World" 3
python crypto_tools/crypto_analyzer.py file-encrypt crypto_tools/sample_document.txt aes
python crypto_tools/crypto_analyzer.py analyze "SGVsbG8=" --json
python -B -m unittest discover -s crypto_tools -p "test_*.py" -v
```

Requires Python 3.10+. Optional dependencies: `python -m pip install cryptography Pillow`. Save generated keys separately; result reports may contain secrets. See the tool README for legacy recovery, changed formats, and limits.

## Digital Conscience: Python code review

Review Python source without importing or executing it. The rewritten tool reports potential performance bottlenecks, correctness issues, security concerns, and documentation/maintenance improvements, with source locations, confidence, explanations, and practical recommendations.

```console
python code_quality/digital_conscience.py scan code_quality/test_sample.py
python code_quality/digital_conscience.py scan ./code_quality --category performance
python code_quality/digital_conscience.py scan ./code_quality --format json --output review.json
python code_quality/digital_conscience.py rules
```

Requires Python 3.10+ and only the standard library. Supports rule/category filters, exclusions, inline suppressions, configurable severity thresholds, and text or JSON reports. Exit codes are `0` for a completed scan below the selected threshold, `1` for findings meeting it, and `2` for errors. The default failure threshold is `high`; the demonstration sample intentionally triggers it.

Launch `python code_quality/digital_conscience.py` without arguments for interactive commands, or use the CLI examples above. Reports include a documented 0-10 rule-based rating and terminal-aware severity colors. This version replaces the former regex-based multi-language checks. Performance findings are suggestions to investigate, not measured runtime results. See the [Digital Conscience README](code_quality/README.md) for rules, CLI options, limitations, migration notes, and tests.

```console
python -B -m unittest discover -s code_quality -p "test_*.py" -v
```

## 📝 Contributing

Feel free to contribute additional Python tools and utilities! Please:
- Follow existing code style and commenting patterns
- Include appropriate documentation
- Test thoroughly before submission
- Add examples for new features

## 📄 License

This software is intended for educational and authorized professional use. Users are responsible for ensuring they have proper authorization before using these tools in professional environments.

## 👤 Author

**Andrew Piggot**

## 🤝 Purpose

Created for educational purposes and authorized penetration testing scenarios.

---

**⚠️ DISCLAIMER:** Any tools made are for educational and authorized testing only. Unauthorized use may violate laws in your jurisdiction. Users assume all responsibility for legal and ethical use.
