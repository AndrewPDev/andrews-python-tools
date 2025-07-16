# Database Security Auditor

A comprehensive database security assessment and auditing tool for identifying vulnerabilities, misconfigurations, and compliance issues.

## Overview

The Database Security Auditor performs thorough security assessments of database systems, focusing on SQLite databases with extensibility for other database types. It provides detailed analysis of security configurations, data classification, vulnerability assessment, and compliance checking.

## Features

### Core Security Assessment
- **Connection Security Analysis** - File permissions, encryption status, backup detection
- **Configuration Audit** - Security settings, pragmas, and database configuration
- **Schema Security Review** - Table structure, indexes, triggers, and design patterns
- **Sensitive Data Classification** - PII detection, credit card numbers, SSNs, emails
- **Vulnerability Assessment** - SQL injection risks, access control issues, data exposure
- **Compliance Checking** - GDPR, PCI-DSS, HIPAA basic compliance assessment

### Database Support
- **SQLite** - Full audit capabilities with comprehensive analysis
- **MySQL** - Connection testing (requires mysql-connector-python)
- **PostgreSQL** - Connection testing (requires psycopg2)
- **MongoDB** - Placeholder for future implementation
- **MS SQL Server** - Placeholder for future implementation

### Security Features
- **Sensitive Data Detection** - Credit cards, SSNs, emails, phone numbers, API keys
- **Pattern Analysis** - Regex-based detection of sensitive information
- **Risk Assessment** - Comprehensive risk scoring and categorization
- **Compliance Framework** - Basic GDPR, PCI-DSS, and HIPAA assessment

## Installation

### Basic Installation
```bash
# Clone repository (if not already done)
git clone https://github.com/AndrewPDev/andrews-python-tools.git
cd andrews-python-tools/database_tools

# Run the database auditor (SQLite support only)
python db_auditor.py
```

### Full Installation (with database drivers)
```bash
# Install optional dependencies for additional database support
pip install mysql-connector-python  # For MySQL support
pip install psycopg2-binary         # For PostgreSQL support
pip install pymongo                 # For MongoDB support

# Run with all features
python db_auditor.py
```

## Usage Examples

### Interactive Mode
```bash
python db_auditor.py
db-auditor> help
```

### Basic Database Audit
```bash
# Generate sample database for testing
db-auditor> generate sample

# Audit SQLite database
db-auditor> audit sqlite sample_database.db

# Test database connection
db-auditor> test sqlite my_database.db
```

### Advanced Usage
```bash
# MySQL database audit (placeholder)
db-auditor> audit mysql "host=localhost,user=root,password=pass,database=testdb"

# PostgreSQL database audit (placeholder)
db-auditor> audit postgresql "host=localhost,user=postgres,password=pass,database=testdb"

# Export audit results
db-auditor> export security_audit_report.json
```

## Sample Analysis Output

```
==============================================================
DATABASE SECURITY AUDIT REPORT
==============================================================
Database Type: SQLITE
Audit Time: 2025-01-10T15:30:45
Overall Security Score: 6.8/10 (Good)
==============================================================

🔌 CONNECTION ANALYSIS
Score: 7/10
File Size: 32,768 bytes
Encryption: ❌ No
Issues Found:
   ⚠️  Database is not encrypted

⚙️  CONFIGURATION AUDIT
Score: 6/10
Security Settings:
   foreign_keys: 0
   secure_delete: 0
Configuration Issues:
   ⚠️  Foreign key constraints are disabled
   ⚠️  Secure delete is disabled - deleted data may be recoverable

🔍 DATA CLASSIFICATION
Score: 4/10
Sensitive Data Detected:
   📍 customers.email: email
   📍 customers.ssn: ssn
   📍 customers.credit_card: credit_card
Compliance Concerns:
   ⚖️  PCI-DSS compliance required for credit card data
   ⚖️  Additional protection required for SSN data

💡 SECURITY RECOMMENDATIONS
   1. Implement database encryption to protect data at rest
   2. Enable foreign key constraints for data integrity
   3. Enable secure delete to prevent data recovery
   4. Implement data masking or encryption for sensitive personal data
   5. Address compliance requirement: PCI-DSS compliance required for credit card data
```

## Security Assessment Areas

### 1. Connection Security
- File permission analysis
- Encryption status detection
- Backup file identification
- Access control evaluation

### 2. Configuration Audit
- SQLite pragma settings review
- Security configuration analysis
- Database hardening assessment
- Performance vs security trade-offs

### 3. Schema Analysis
- Table structure security review
- Primary key and foreign key analysis
- Audit trail detection
- Sensitive column identification

### 4. Data Classification
- Sensitive data pattern detection
- PII identification and categorization
- Compliance requirement mapping
- Data retention analysis

### 5. Vulnerability Assessment
- SQL injection risk analysis
- Access control weaknesses
- Configuration vulnerabilities
- Data exposure risks

### 6. Compliance Framework
- GDPR basic compliance check
- PCI-DSS requirements assessment
- HIPAA security analysis
- Industry standard recommendations

## Supported Data Types for Detection

| Data Type | Pattern | Compliance Impact |
|-----------|---------|-------------------|
| Credit Cards | Visa, MasterCard, Amex patterns | PCI-DSS required |
| SSN | XXX-XX-XXXX format | Privacy protection required |
| Email Addresses | Standard email format | GDPR considerations |
| Phone Numbers | Various phone formats | Privacy regulations |
| IP Addresses | IPv4 format | Technical security |
| Password Hashes | bcrypt, scrypt patterns | Authentication security |
| API Keys | Common API key patterns | Access control |

## Command Reference

```bash
# Database Auditing
audit sqlite <file_path>               # Full SQLite database audit
audit mysql <connection_string>        # MySQL audit (placeholder)
audit postgresql <connection_string>   # PostgreSQL audit (placeholder)

# Connection Testing
test sqlite <file_path>                # Test SQLite connection
test mysql <connection_string>         # Test MySQL connection

# Sample Data
generate sample                        # Create sample SQLite database

# Results Management
export <filename.json>                 # Export audit results to JSON

# Help and Information
help                                   # Show command help
quit, exit                            # Exit the program
```

## Security Scoring System

All assessments use a 0-10 scoring system:

| Score | Rating | Description |
|-------|--------|-------------|
| 8-10 | Excellent | Strong security posture, minimal issues |
| 6-7 | Good | Solid security with minor improvements needed |
| 4-5 | Fair | Moderate security concerns requiring attention |
| 0-3 | Poor | Significant security issues requiring immediate action |

## Data Flow and Security

### Audit Process
1. **Connection Analysis** - Database accessibility and basic security
2. **Configuration Review** - Security settings and hardening
3. **Schema Assessment** - Database design security
4. **Data Classification** - Sensitive data identification
5. **Vulnerability Scanning** - Security weakness detection
6. **Compliance Mapping** - Regulatory requirement assessment
7. **Risk Scoring** - Overall security posture calculation
8. **Recommendation Generation** - Actionable security improvements

### Security Considerations
- **Read-Only Analysis** - Tool performs read-only operations on databases
- **Pattern Detection** - Uses regex patterns for sensitive data identification
- **Local Processing** - All analysis performed locally, no data transmission
- **Audit Logging** - Comprehensive logging of audit activities

## Sample Database Structure

The generated sample database includes:

### Tables
- **users** - User authentication data with proper security practices
- **customers** - Customer data with various PII for testing detection
- **audit_logs** - Audit trail table for compliance demonstration
- **products** - Business data for completeness

### Security Scenarios
- Encrypted password hashes (bcrypt)
- Sensitive PII data (SSN, credit cards, emails)
- Audit trail implementation
- Mixed security configurations for testing

## Error Handling

The tool includes comprehensive error handling for:
- Database connection failures
- File permission issues
- Malformed database files
- Invalid SQL queries
- Missing dependencies
- Network connectivity issues

## Educational Value

This tool demonstrates:
- Database security assessment methodologies
- Sensitive data identification techniques
- Compliance framework basics
- Security scoring and risk assessment
- Database hardening principles
- Audit trail importance

Perfect for:
- Security professionals learning database assessment
- Database administrators improving security posture
- Compliance teams understanding requirements
- Educational environments teaching database security

## Limitations

### Current Implementation
- SQLite databases fully supported
- Other databases require specific drivers for full functionality
- Basic compliance checking (not comprehensive audit)
- Pattern-based detection may have false positives/negatives

### Future Enhancements
- Full MySQL and PostgreSQL support
- Advanced SQL injection testing
- Real-time monitoring capabilities
- Integration with security tools
- Enhanced compliance frameworks

## Security Notes

### Educational Purpose
- This tool is designed for educational and authorized testing only
- Always ensure proper authorization before auditing databases
- Use in compliance with organizational policies and legal requirements

### Data Privacy
- Tool operates in read-only mode to prevent data modification
- Sensitive data detection results should be handled securely
- Consider data privacy regulations when sharing audit results

### Professional Use
- Recommended for use by qualified security professionals
- Results should be verified with additional security tools
- Consider professional security assessment for critical systems

---

**⚠️ DISCLAIMER:** This tool is for educational and authorized testing only. Users are responsible for ensuring proper authorization and compliance with applicable laws and regulations.
