"""
Database Security Auditor

Author:
Andrew Piggot

Purpose: 
Comprehensive database security assessment and auditing tool

Usage: 
Educational purposes, authorized penetration testing, and security auditing
"""

import re
import sys
import json
import sqlite3
import hashlib
import secrets
import socket
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

class DBTool:
    
    def __init__( self ):
        self.supported_databases = ['sqlite', 'mysql', 'postgresql', 'mongodb', 'mssql']
        self.audit_results = {}
        self.security_score = 0
        self.vulnerabilities = []
        self.recommendations = []
        self.connection_details = {}
        self.script_dir = Path( __file__ ).parent.absolute()
        
        # Security patterns for detection
        self.sensitive_patterns = {
            'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'ssn': r'\b(?:\d{3}-?\d{2}-?\d{4})\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'password_hash': r'\$2[ayb]\$.{56}',
            'api_key': r'(?i)(?:api[_-]?key|token|secret)[\'"\s]*[:=][\'"\s]*[a-zA-Z0-9_-]{20,}'
        }
        
        # Common weak passwords
        self.weak_passwords = [
            'password', '123456', 'admin', 'root', 'guest', 'user', 'test',
            'password123', 'admin123', 'qwerty', 'letmein', 'welcome',
            'database', 'db', 'sql', 'oracle', 'mysql', 'postgres'
        ]
        
        # SQL injection test payloads
        self.sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL,NULL,NULL--",
            "admin'--",
            "' OR 1=1#",
            "1' AND SLEEP(5)--",
            "' WAITFOR DELAY '00:00:05'--"
        ]
    
    # Main audit function
    def Audit( self, db_type: str, connection_string: str = None, file_path: str = None ) -> Dict:
        """Perform comprehensive database security audit"""
        try:
            print( f"\n{'='*60}" )
            print( f"DATABASE SECURITY AUDIT - {db_type.upper()}" )
            print( f"{'='*60}" )
            
            self.audit_results = {
                'database_type': db_type,
                'audit_timestamp': datetime.now().isoformat(),
                'connection_analysis': {},
                'configuration_audit': {},
                'user_analysis': {},
                'data_classification': {},
                'vulnerability_assessment': {},
                'compliance_check': {},
                'overall_score': 0,
                'security_level': 'Unknown',
                'vulnerabilities': [],
                'recommendations': []
            }
            
            if db_type.lower() == 'sqlite':
                if file_path:
                    self._AuditSQLite( file_path )
                else:
                    return {'error': 'SQLite database file path required'}
            else:
                if connection_string:
                    self._AuditRemote( db_type, connection_string )
                else:
                    return {'error': f'{db_type} connection string required'}
            
            # Calculate overall security score
            self._CalcScore()
            
            # Generate recommendations
            self._GenRecs()
            
            return self.audit_results
            
        except Exception as e:
            return {
                'error': f'Database audit failed: {str( e )}',
                'timestamp': datetime.now().isoformat()
            }
    
    # SQLite database audit
    def _AuditSQLite( self, file_path: str ):
        """Audit SQLite database file"""
        try:
            if not Path( file_path ).exists():
                raise FileNotFoundError( f"Database file not found: {file_path}" )
            
            # Connection analysis
            self.audit_results['connection_analysis'] = self._AnalyzeConn( file_path )
            
            # Connect to database
            conn = sqlite3.connect( file_path )
            cursor = conn.cursor()
            
            # Configuration audit
            self.audit_results['configuration_audit'] = self._AuditConfig( cursor )
            
            # Schema analysis
            self.audit_results['schema_analysis'] = self._AnalyzeSchema( cursor )
            
            # Data classification
            self.audit_results['data_classification'] = self._ClassifyData( cursor )
            
            # Vulnerability assessment
            self.audit_results['vulnerability_assessment'] = self._CheckVulns( cursor, 'sqlite' )
            
            # Compliance check
            self.audit_results['compliance_check'] = self._CheckCompliance( cursor, 'sqlite' )
            
            conn.close()
            
        except Exception as e:
            self.audit_results['error'] = f"SQLite audit failed: {str( e )}"
    
    # Remote database audit (MySQL, PostgreSQL, etc.)
    def _AuditRemote( self, db_type: str, connection_string: str ):
        """Audit remote database (placeholder for extensibility)"""
        self.audit_results['connection_analysis'] = {
            'database_type': db_type,
            'connection_method': 'remote',
            'encryption': 'unknown',
            'status': 'Connection testing not implemented for remote databases',
            'score': 5
        }
        
        # Add placeholder results for remote databases
        self.audit_results['configuration_audit'] = {
            'status': 'Remote database auditing requires specific drivers',
            'recommendation': f'Install {db_type} Python driver for full audit capabilities',
            'score': 5
        }
    
    # Analyze SQLite connection security
    def _AnalyzeConn( self, file_path: str ) -> Dict:
        """Analyze SQLite file security"""
        analysis = {
            'file_path': file_path,
            'file_size': 0,
            'permissions': 'unknown',
            'encryption': False,
            'backup_detected': False,
            'issues': [],
            'score': 0
        }
        
        try:
            file_stat = Path( file_path ).stat()
            analysis['file_size'] = file_stat.st_size
            
            # Check file permissions (basic check)
            if file_stat.st_mode & 0o077:
                analysis['issues'].append( 'Database file has overly permissive permissions' )
            
            # Check for encryption (SQLite)
            with open( file_path, 'rb' ) as f:
                header = f.read( 16 )
                if header.startswith( b'SQLite format 3' ):
                    analysis['encryption'] = False
                    analysis['issues'].append( 'Database is not encrypted' )
                else:
                    analysis['encryption'] = True
            
            # Check for backup files
            backup_patterns = ['.bak', '.backup', '.old', '_backup']
            for pattern in backup_patterns:
                if Path( file_path + pattern ).exists():
                    analysis['backup_detected'] = True
                    analysis['issues'].append( f'Backup file detected: {file_path + pattern}' )
            
            # Calculate score
            score = 10
            score -= len( analysis['issues'] ) * 2
            analysis['score'] = max( 0, score )
            
        except Exception as e:
            analysis['error'] = str( e )
            analysis['score'] = 0
        
        return analysis
    
    # Audit SQLite configuration
    def _AuditConfig( self, cursor ) -> Dict:
        """Audit SQLite configuration settings"""
        config = {
            'pragmas': {},
            'security_settings': {},
            'issues': [],
            'score': 0
        }
        
        try:
            # Check important SQLite pragmas
            important_pragmas = [
                'foreign_keys', 'journal_mode', 'synchronous',
                'secure_delete', 'temp_store', 'auto_vacuum'
            ]
            
            for pragma in important_pragmas:
                try:
                    cursor.execute( f"PRAGMA {pragma}" )
                    result = cursor.fetchone()
                    config['pragmas'][pragma] = result[0] if result else None
                except:
                    config['pragmas'][pragma] = 'unavailable'
            
            # Analyze security implications
            if config['pragmas'].get( 'foreign_keys' ) != 1:
                config['issues'].append( 'Foreign key constraints are disabled' )
            
            if config['pragmas'].get( 'secure_delete' ) != 1:
                config['issues'].append( 'Secure delete is disabled - deleted data may be recoverable' )
            
            # Calculate score
            score = 8
            score -= len( config['issues'] ) * 2
            config['score'] = max( 0, score )
            
        except Exception as e:
            config['error'] = str( e )
            config['score'] = 0
        
        return config
    
    # Analyze database schema
    def _AnalyzeSchema( self, cursor ) -> Dict:
        """Analyze database schema for security issues"""
        schema = {
            'tables': [],
            'indexes': [],
            'triggers': [],
            'views': [],
            'security_issues': [],
            'score': 0
        }
        
        try:
            # Get all tables
            cursor.execute( "SELECT name FROM sqlite_master WHERE type='table'" )
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                schema['tables'].append( table_name )
                
                # Analyze table structure
                cursor.execute( f"PRAGMA table_info({table_name})" )
                columns = cursor.fetchall()
                
                # Check for security issues in table design
                has_id_column = False
                has_timestamps = False
                sensitive_columns = []
                
                for column in columns:
                    col_name = column[1].lower()
                    col_type = column[2].lower()
                    
                    if 'id' in col_name and column[5]:  # Primary key
                        has_id_column = True
                    
                    if any( ts in col_name for ts in ['created', 'updated', 'timestamp', 'date'] ):
                        has_timestamps = True
                    
                    # Check for sensitive data columns
                    if any( sens in col_name for sens in ['password', 'credit_card', 'ssn', 'secret', 'key'] ):
                        sensitive_columns.append( col_name )
                
                if not has_id_column:
                    schema['security_issues'].append( f"Table '{table_name}' lacks proper primary key" )
                
                if not has_timestamps:
                    schema['security_issues'].append( f"Table '{table_name}' lacks audit timestamps" )
                
                if sensitive_columns:
                    schema['security_issues'].append( f"Table '{table_name}' contains sensitive columns: {', '.join( sensitive_columns )}" )
            
            # Get indexes
            cursor.execute( "SELECT name FROM sqlite_master WHERE type='index'" )
            indexes = cursor.fetchall()
            schema['indexes'] = [idx[0] for idx in indexes if idx[0]]
            
            # Get triggers
            cursor.execute( "SELECT name FROM sqlite_master WHERE type='trigger'" )
            triggers = cursor.fetchall()
            schema['triggers'] = [trig[0] for trig in triggers]
            
            # Get views
            cursor.execute( "SELECT name FROM sqlite_master WHERE type='view'" )
            views = cursor.fetchall()
            schema['views'] = [view[0] for view in views]
            
            # Calculate score
            score = 8
            score -= len( schema['security_issues'] ) * 1
            schema['score'] = max( 0, score )
            
        except Exception as e:
            schema['error'] = str( e )
            schema['score'] = 0
        
        return schema
    
    # Classify sensitive data
    def _ClassifyData( self, cursor ) -> Dict:
        """Classify and identify sensitive data in database"""
        classification = {
            'sensitive_data_found': {},
            'data_types': {},
            'privacy_concerns': [],
            'compliance_issues': [],
            'score': 0
        }
        
        try:
            # Get all tables
            cursor.execute( "SELECT name FROM sqlite_master WHERE type='table'" )
            tables = cursor.fetchall()
            
            total_sensitive_findings = 0
            
            for table in tables:
                table_name = table[0]
                
                try:
                    # Sample data from table (limit for performance)
                    cursor.execute( f"SELECT * FROM {table_name} LIMIT 100" )
                    rows = cursor.fetchall()
                    
                    # Get column names
                    cursor.execute( f"PRAGMA table_info({table_name})" )
                    columns = cursor.fetchall()
                    column_names = [col[1] for col in columns]
                    
                    # Analyze data for sensitive patterns
                    for row in rows:
                        for i, value in enumerate( row ):
                            if value and isinstance( value, str ):
                                for pattern_name, pattern in self.sensitive_patterns.items():
                                    if re.search( pattern, str( value ) ):
                                        key = f"{table_name}.{column_names[i]}"
                                        if key not in classification['sensitive_data_found']:
                                            classification['sensitive_data_found'][key] = []
                                        if pattern_name not in classification['sensitive_data_found'][key]:
                                            classification['sensitive_data_found'][key].append( pattern_name )
                                            total_sensitive_findings += 1
                
                except Exception as e:
                    # Skip tables that can't be accessed
                    continue
            
            # Analyze findings
            if total_sensitive_findings > 0:
                classification['privacy_concerns'].append( f"Found {total_sensitive_findings} potential sensitive data instances" )
                
                # Check for specific compliance requirements
                sensitive_types = []
                for findings in classification['sensitive_data_found'].values():
                    sensitive_types.extend( findings )
                
                if 'credit_card' in sensitive_types:
                    classification['compliance_issues'].append( 'PCI-DSS compliance required for credit card data' )
                
                if 'ssn' in sensitive_types:
                    classification['compliance_issues'].append( 'Additional protection required for SSN data' )
                
                if 'email' in sensitive_types:
                    classification['compliance_issues'].append( 'GDPR compliance may be required for email addresses' )
            
            # Calculate score (lower score for more sensitive data)
            score = 8
            if total_sensitive_findings > 0:
                score -= min( total_sensitive_findings * 0.5, 6 )
            classification['score'] = max( 0, score )
            
        except Exception as e:
            classification['error'] = str( e )
            classification['score'] = 5
        
        return classification
    
    # Assess database vulnerabilities
    def _CheckVulns( self, cursor, db_type: str ) -> Dict:
        """Assess database for common vulnerabilities"""
        assessment = {
            'injection_vulnerabilities': [],
            'access_control_issues': [],
            'configuration_weaknesses': [],
            'data_exposure_risks': [],
            'total_vulnerabilities': 0,
            'risk_level': 'Low',
            'score': 0
        }
        
        try:
            # Check for SQL injection vulnerabilities (simulated)
            # Note: This is educational and doesn't actually test injection
            cursor.execute( "SELECT name FROM sqlite_master WHERE type='table'" )
            tables = cursor.fetchall()
            
            vulnerable_patterns = 0
            
            for table in tables:
                table_name = table[0]
                
                # Check for tables that might be vulnerable
                if any( vuln in table_name.lower() for vuln in ['user', 'admin', 'login', 'auth'] ):
                    assessment['injection_vulnerabilities'].append( 
                        f"Table '{table_name}' may be target for SQL injection attacks" 
                    )
                    vulnerable_patterns += 1
            
            # Check for weak access patterns (educational simulation)
            if vulnerable_patterns > 0:
                assessment['access_control_issues'].append( 
                    "Database contains authentication-related tables that require protection" 
                )
            
            # Check for data exposure risks
            cursor.execute( "SELECT name FROM sqlite_master WHERE type='table'" )
            table_count = len( cursor.fetchall() )
            
            if table_count > 10:
                assessment['data_exposure_risks'].append( 
                    "Large number of tables increases attack surface" 
                )
            
            # Check for configuration weaknesses
            try:
                cursor.execute( "PRAGMA journal_mode" )
                journal_mode = cursor.fetchone()[0]
                if journal_mode.lower() == 'delete':
                    assessment['configuration_weaknesses'].append( 
                        "Journal mode 'DELETE' may allow data recovery from deleted records" 
                    )
            except:
                pass
            
            # Calculate total vulnerabilities
            assessment['total_vulnerabilities'] = (
                len( assessment['injection_vulnerabilities'] ) +
                len( assessment['access_control_issues'] ) +
                len( assessment['configuration_weaknesses'] ) +
                len( assessment['data_exposure_risks'] )
            )
            
            # Determine risk level
            if assessment['total_vulnerabilities'] == 0:
                assessment['risk_level'] = 'Low'
                assessment['score'] = 9
            elif assessment['total_vulnerabilities'] <= 2:
                assessment['risk_level'] = 'Medium'
                assessment['score'] = 6
            else:
                assessment['risk_level'] = 'High'
                assessment['score'] = 3
            
        except Exception as e:
            assessment['error'] = str( e )
            assessment['score'] = 5
        
        return assessment
    
    # Check compliance requirements
    def _CheckCompliance( self, cursor, db_type: str ) -> Dict:
        """Check database compliance with security standards"""
        compliance = {
            'gdpr_compliance': {},
            'pci_dss_compliance': {},
            'hipaa_compliance': {},
            'general_compliance': {},
            'compliance_score': 0,
            'issues': [],
            'recommendations': []
        }
        
        try:
            # GDPR compliance checks
            gdpr_score = 8
            
            # Check for personal data protection
            cursor.execute( "SELECT name FROM sqlite_master WHERE type='table'" )
            tables = cursor.fetchall()
            
            has_audit_trail = False
            has_encryption = False
            has_access_controls = False
            
            for table in tables:
                table_name = table[0].lower()
                if 'log' in table_name or 'audit' in table_name:
                    has_audit_trail = True
                if 'user' in table_name or 'account' in table_name:
                    # Check if there are proper access controls
                    cursor.execute( f"PRAGMA table_info({table[0]})" )
                    columns = cursor.fetchall()
                    column_names = [col[1].lower() for col in columns]
                    if any( 'role' in col or 'permission' in col for col in column_names ):
                        has_access_controls = True
            
            if not has_audit_trail:
                compliance['issues'].append( 'No audit trail detected (GDPR requirement)' )
                gdpr_score -= 2
            
            if not has_encryption:
                compliance['issues'].append( 'Database encryption not detected (GDPR recommendation)' )
                gdpr_score -= 2
            
            if not has_access_controls:
                compliance['issues'].append( 'Access control mechanisms not clearly defined' )
                gdpr_score -= 2
            
            compliance['gdpr_compliance'] = {
                'score': max( 0, gdpr_score ),
                'audit_trail': has_audit_trail,
                'encryption': has_encryption,
                'access_controls': has_access_controls
            }
            
            # PCI-DSS compliance (basic check)
            pci_score = 8
            compliance['pci_dss_compliance'] = {
                'score': pci_score,
                'status': 'Basic assessment - full PCI audit requires specialized tools'
            }
            
            # HIPAA compliance (basic check)
            hipaa_score = 8
            compliance['hipaa_compliance'] = {
                'score': hipaa_score,
                'status': 'Basic assessment - full HIPAA audit requires specialized tools'
            }
            
            # Calculate overall compliance score
            compliance['compliance_score'] = (
                compliance['gdpr_compliance']['score'] +
                compliance['pci_dss_compliance']['score'] +
                compliance['hipaa_compliance']['score']
            ) // 3
            
        except Exception as e:
            compliance['error'] = str( e )
            compliance['compliance_score'] = 5
        
        return compliance
    
    # Calculate overall security score
    def _CalcScore( self ):
        """Calculate overall database security score"""
        scores = []
        
        # Collect all scores
        if 'connection_analysis' in self.audit_results:
            scores.append( self.audit_results['connection_analysis'].get( 'score', 5 ) )
        
        if 'configuration_audit' in self.audit_results:
            scores.append( self.audit_results['configuration_audit'].get( 'score', 5 ) )
        
        if 'schema_analysis' in self.audit_results:
            scores.append( self.audit_results['schema_analysis'].get( 'score', 5 ) )
        
        if 'data_classification' in self.audit_results:
            scores.append( self.audit_results['data_classification'].get( 'score', 5 ) )
        
        if 'vulnerability_assessment' in self.audit_results:
            scores.append( self.audit_results['vulnerability_assessment'].get( 'score', 5 ) )
        
        if 'compliance_check' in self.audit_results:
            scores.append( self.audit_results['compliance_check'].get( 'compliance_score', 5 ) )
        
        # Calculate average score
        if scores:
            self.security_score = sum( scores ) / len( scores )
        else:
            self.security_score = 5
        
        self.audit_results['overall_score'] = round( self.security_score, 1 )
        
        # Determine security level
        if self.security_score >= 8:
            self.audit_results['security_level'] = 'Excellent'
        elif self.security_score >= 6:
            self.audit_results['security_level'] = 'Good'
        elif self.security_score >= 4:
            self.audit_results['security_level'] = 'Fair'
        else:
            self.audit_results['security_level'] = 'Poor'
    
    # Generate security recommendations
    def _GenRecs( self ):
        """Generate security recommendations based on audit results"""
        recommendations = []
        
        # Connection security recommendations
        if 'connection_analysis' in self.audit_results:
            conn_analysis = self.audit_results['connection_analysis']
            if 'encryption' in conn_analysis and not conn_analysis['encryption']:
                recommendations.append( 'Implement database encryption to protect data at rest' )
            
            if 'issues' in conn_analysis:
                for issue in conn_analysis['issues']:
                    if 'permission' in issue.lower():
                        recommendations.append( 'Restrict database file permissions to prevent unauthorized access' )
                    if 'backup' in issue.lower():
                        recommendations.append( 'Secure or remove backup files to prevent data leakage' )
        
        # Configuration recommendations
        if 'configuration_audit' in self.audit_results:
            config_audit = self.audit_results['configuration_audit']
            if 'issues' in config_audit:
                for issue in config_audit['issues']:
                    if 'foreign_keys' in issue:
                        recommendations.append( 'Enable foreign key constraints for data integrity' )
                    if 'secure_delete' in issue:
                        recommendations.append( 'Enable secure delete to prevent data recovery' )
        
        # Schema recommendations
        if 'schema_analysis' in self.audit_results:
            schema_analysis = self.audit_results['schema_analysis']
            if 'security_issues' in schema_analysis:
                for issue in schema_analysis['security_issues']:
                    if 'primary key' in issue:
                        recommendations.append( 'Add proper primary keys to all tables for data integrity' )
                    if 'timestamps' in issue:
                        recommendations.append( 'Add audit timestamps to track data changes' )
                    if 'sensitive columns' in issue:
                        recommendations.append( 'Implement encryption for sensitive data columns' )
        
        # Data classification recommendations
        if 'data_classification' in self.audit_results:
            data_class = self.audit_results['data_classification']
            if 'privacy_concerns' in data_class and data_class['privacy_concerns']:
                recommendations.append( 'Implement data masking or encryption for sensitive personal data' )
                recommendations.append( 'Review data retention policies for sensitive information' )
            
            if 'compliance_issues' in data_class:
                for issue in data_class['compliance_issues']:
                    recommendations.append( f'Address compliance requirement: {issue}' )
        
        # Vulnerability recommendations
        if 'vulnerability_assessment' in self.audit_results:
            vuln_assessment = self.audit_results['vulnerability_assessment']
            if vuln_assessment.get( 'risk_level' ) in ['Medium', 'High']:
                recommendations.append( 'Implement input validation and parameterized queries to prevent SQL injection' )
                recommendations.append( 'Regular security assessments and penetration testing recommended' )
            
            if vuln_assessment.get( 'total_vulnerabilities', 0 ) > 0:
                recommendations.append( 'Review and harden database configuration settings' )
                recommendations.append( 'Implement proper access controls and user authentication' )
        
        # Compliance recommendations
        if 'compliance_check' in self.audit_results:
            compliance = self.audit_results['compliance_check']
            if compliance.get( 'compliance_score', 0 ) < 7:
                recommendations.append( 'Implement audit logging for compliance requirements' )
                recommendations.append( 'Review and document data handling procedures' )
                recommendations.append( 'Consider professional compliance assessment' )
        
        # General recommendations
        if self.security_score < 6:
            recommendations.append( 'Conduct comprehensive security review with database administrator' )
            recommendations.append( 'Implement database activity monitoring (DAM) solution' )
            recommendations.append( 'Regular backup testing and disaster recovery planning' )
        
        self.audit_results['recommendations'] = recommendations
    
    # Test database connection
    def TestConn( self, db_type: str, connection_string: str = None, file_path: str = None ) -> Dict:
        """Test database connection without full audit"""
        result = {
            'database_type': db_type,
            'connection_status': 'unknown',
            'error': None,
            'basic_info': {}
        }
        
        try:
            if db_type.lower() == 'sqlite':
                if not file_path:
                    result['error'] = 'SQLite file path required'
                    return result
                
                if not Path( file_path ).exists():
                    result['error'] = f'Database file not found: {file_path}'
                    return result
                
                conn = sqlite3.connect( file_path )
                cursor = conn.cursor()
                
                # Get basic database info
                cursor.execute( "SELECT COUNT(*) FROM sqlite_master WHERE type='table'" )
                table_count = cursor.fetchone()[0]
                
                result['basic_info'] = {
                    'file_size': Path( file_path ).stat().st_size,
                    'table_count': table_count,
                    'sqlite_version': sqlite3.sqlite_version
                }
                
                result['connection_status'] = 'success'
                conn.close()
                
            else:
                result['error'] = f'Connection testing for {db_type} not implemented (requires specific drivers)'
                result['connection_status'] = 'not_implemented'
            
        except Exception as e:
            result['error'] = str( e )
            result['connection_status'] = 'failed'
        
        return result
    
    # Generate sample database for testing
    def GenSample( self, file_path: str = None ) -> Dict:
        """Generate sample SQLite database for testing"""
        if not file_path:
            file_path = self.script_dir / 'sample_database.db'
        
        try:
            # Remove existing file
            if Path( file_path ).exists():
                Path( file_path ).unlink()
            
            conn = sqlite3.connect( file_path )
            cursor = conn.cursor()
            
            # Create sample tables with various security scenarios
            
            # Users table (good security practices)
            cursor.execute( '''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''' )
            
            # Customer data table (contains sensitive data)
            cursor.execute( '''
                CREATE TABLE customers (
                    id INTEGER PRIMARY KEY,
                    first_name TEXT,
                    last_name TEXT,
                    email TEXT,
                    phone TEXT,
                    ssn TEXT,
                    credit_card TEXT,
                    address TEXT
                )
            ''' )
            
            # Logs table (audit trail)
            cursor.execute( '''
                CREATE TABLE audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT,
                    table_name TEXT,
                    record_id INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT
                )
            ''' )
            
            # Products table (business data)
            cursor.execute( '''
                CREATE TABLE products (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    price DECIMAL(10,2),
                    category TEXT
                )
            ''' )
            
            # Insert sample data
            
            # Sample users
            sample_users = [
                ('admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4fO9/cF6Ku', 'admin'),
                ('john_doe', 'john@example.com', '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user'),
                ('jane_smith', 'jane@example.com', '$2b$12$gLIBoFI8nKW0KLHJ0ZvjVu2M8EQKWczL.h6MTHZ4eEd5Dj8jQ.O6e', 'user')
            ]
            
            for user in sample_users:
                cursor.execute( 'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)', user )
            
            # Sample customers (with sensitive data)
            sample_customers = [
                (1, 'Alice', 'Johnson', 'alice@email.com', '555-123-4567', '123-45-6789', '4532015112830366', '123 Main St'),
                (2, 'Bob', 'Wilson', 'bob@email.com', '555-987-6543', '987-65-4321', '5555555555554444', '456 Oak Ave'),
                (3, 'Carol', 'Brown', 'carol@email.com', '555-555-5555', '555-55-5555', '4000000000000002', '789 Pine Rd')
            ]
            
            for customer in sample_customers:
                cursor.execute( 'INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?, ?)', customer )
            
            # Sample audit logs
            sample_logs = [
                (1, 'LOGIN', 'users', 1, '192.168.1.100'),
                (1, 'UPDATE', 'customers', 1, '192.168.1.100'),
                (2, 'SELECT', 'products', None, '192.168.1.101')
            ]
            
            for log in sample_logs:
                cursor.execute( 'INSERT INTO audit_logs (user_id, action, table_name, record_id, ip_address) VALUES (?, ?, ?, ?, ?)', log )
            
            # Sample products
            sample_products = [
                (1, 'Laptop Computer', 'High-performance laptop', 999.99, 'Electronics'),
                (2, 'Office Chair', 'Ergonomic office chair', 299.99, 'Furniture'),
                (3, 'Wireless Mouse', 'Bluetooth wireless mouse', 29.99, 'Electronics')
            ]
            
            for product in sample_products:
                cursor.execute( 'INSERT INTO products VALUES (?, ?, ?, ?, ?)', product )
            
            conn.commit()
            conn.close()
            
            return {
                'status': 'success',
                'message': f'Sample database created: {file_path}',
                'file_path': str( file_path ),
                'tables_created': ['users', 'customers', 'audit_logs', 'products'],
                'sample_data': 'Included realistic test data with security scenarios'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Failed to create sample database: {str( e )}'
            }
    
    # Display audit results
    def ShowResults( self, results: Dict ):
        """Display formatted audit results"""
        if 'error' in results:
            print( f"\n[ERROR] {results['error']}" )
            return
        
        print( f"\n{'='*60}" )
        print( f"DATABASE SECURITY AUDIT REPORT" )
        print( f"{'='*60}" )
        print( f"Database Type: {results.get( 'database_type', 'Unknown' ).upper()}" )
        print( f"Audit Time: {results.get( 'audit_timestamp', 'Unknown' )}" )
        print( f"Overall Security Score: {results.get( 'overall_score', 0 )}/10 ({results.get( 'security_level', 'Unknown' )})" )
        print( f"{'='*60}" )
        
        # Connection Analysis
        if 'connection_analysis' in results:
            conn = results['connection_analysis']
            print( f"\n[CONNECTION] CONNECTION ANALYSIS" )
            print( f"Score: {conn.get( 'score', 0 )}/10" )
            if 'file_size' in conn:
                print( f"File Size: {conn['file_size']:,} bytes" )
            print( f"Encryption: {'[YES]' if conn.get( 'encryption' ) else '[NO]'}" )
            if 'issues' in conn and conn['issues']:
                print( f"Issues Found:" )
                for issue in conn['issues']:
                    print( f"   [WARNING] {issue}" )
        
        # Configuration Audit
        if 'configuration_audit' in results:
            config = results['configuration_audit']
            print( f"\n[CONFIG] CONFIGURATION AUDIT" )
            print( f"Score: {config.get( 'score', 0 )}/10" )
            if 'pragmas' in config:
                print( f"Security Settings:" )
                for pragma, value in config['pragmas'].items():
                    print( f"   {pragma}: {value}" )
            if 'issues' in config and config['issues']:
                print( f"Configuration Issues:" )
                for issue in config['issues']:
                    print( f"   [WARNING] {issue}" )
        
        # Schema Analysis
        if 'schema_analysis' in results:
            schema = results['schema_analysis']
            print( f"\n[SCHEMA] SCHEMA ANALYSIS" )
            print( f"Score: {schema.get( 'score', 0 )}/10" )
            print( f"Tables: {len( schema.get( 'tables', [] ) )}" )
            print( f"Indexes: {len( schema.get( 'indexes', [] ) )}" )
            print( f"Triggers: {len( schema.get( 'triggers', [] ) )}" )
            print( f"Views: {len( schema.get( 'views', [] ) )}" )
            if 'security_issues' in schema and schema['security_issues']:
                print( f"Schema Security Issues:" )
                for issue in schema['security_issues']:
                    print( f"   [WARNING] {issue}" )
        
        # Data Classification
        if 'data_classification' in results:
            data_class = results['data_classification']
            print( f"\n[DATA] DATA CLASSIFICATION" )
            print( f"Score: {data_class.get( 'score', 0 )}/10" )
            if 'sensitive_data_found' in data_class and data_class['sensitive_data_found']:
                print( f"Sensitive Data Detected:" )
                for location, types in data_class['sensitive_data_found'].items():
                    print( f"   [LOCATION] {location}: {', '.join( types )}" )
            if 'compliance_issues' in data_class and data_class['compliance_issues']:
                print( f"Compliance Concerns:" )
                for issue in data_class['compliance_issues']:
                    print( f"   [COMPLIANCE] {issue}" )
        
        # Vulnerability Assessment
        if 'vulnerability_assessment' in results:
            vuln = results['vulnerability_assessment']
            print( f"\n[VULN] VULNERABILITY ASSESSMENT" )
            print( f"Score: {vuln.get( 'score', 0 )}/10" )
            print( f"Risk Level: {vuln.get( 'risk_level', 'Unknown' )}" )
            print( f"Total Vulnerabilities: {vuln.get( 'total_vulnerabilities', 0 )}" )
            
            vuln_types = ['injection_vulnerabilities', 'access_control_issues', 'configuration_weaknesses', 'data_exposure_risks']
            for vuln_type in vuln_types:
                if vuln_type in vuln and vuln[vuln_type]:
                    print( f"{vuln_type.replace( '_', ' ' ).title()}:" )
                    for item in vuln[vuln_type]:
                        print( f"   [ALERT] {item}" )
        
        # Compliance Check
        if 'compliance_check' in results:
            compliance = results['compliance_check']
            print( f"\n[COMPLIANCE] COMPLIANCE ASSESSMENT" )
            print( f"Overall Compliance Score: {compliance.get( 'compliance_score', 0 )}/10" )
            
            compliance_frameworks = ['gdpr_compliance', 'pci_dss_compliance', 'hipaa_compliance']
            for framework in compliance_frameworks:
                if framework in compliance:
                    framework_name = framework.replace( '_compliance', '' ).upper()
                    framework_score = compliance[framework].get( 'score', 0 )
                    print( f"{framework_name}: {framework_score}/10" )
        
        # Recommendations
        if 'recommendations' in results and results['recommendations']:
            print( f"\n[RECOMMENDATIONS] SECURITY RECOMMENDATIONS" )
            for i, recommendation in enumerate( results['recommendations'], 1 ):
                print( f"   {i}. {recommendation}" )
        
        print( f"\n{'='*60}" )
    
    # Export audit results
    def Export( self, results: Dict, filename: str ):
        """Export audit results to JSON file"""
        try:
            with open( filename, 'w' ) as f:
                json.dump( results, f, indent=2, default=str )
            print( f"[SUCCESS] Audit results exported to: {filename}" )
        except Exception as e:
            print( f"[ERROR] Failed to export results: {str( e )}" )
    
    # Display help information
    def ShowHelp( self ):
        """Display help information"""
        print( f"\n{'='*60}" )
        print( f"DATABASE SECURITY AUDITOR - HELP" )
        print( f"{'='*60}" )
        print( f"Commands:" )
        print( f"  audit sqlite <file_path>         - Audit SQLite database file" )
        print( f"  audit mysql <connection_string>  - Audit MySQL database (placeholder)" )
        print( f"  audit postgresql <conn_string>   - Audit PostgreSQL database (placeholder)" )
        print( f"  test sqlite <file_path>          - Test SQLite database connection" )
        print( f"  generate sample                  - Generate sample SQLite database" )
        print( f"  export <filename>                - Export last audit results to JSON" )
        print( f"  help                             - Show this help message" )
        print( f"  quit, exit                       - Exit the program" )
        print( f"\nExample Usage:" )
        print( f"  audit sqlite sample_database.db" )
        print( f"  test sqlite my_database.db" )
        print( f"  generate sample" )
        print( f"  export security_audit_report.json" )
        print( f"\nSupported Database Types:" )
        print( f"  [FULL] SQLite (fully supported)" )
        print( f"  [BASIC] MySQL (connection testing only)" )
        print( f"  [BASIC] PostgreSQL (connection testing only)" )
        print( f"  [TODO] MongoDB (placeholder)" )
        print( f"  [TODO] MS SQL Server (placeholder)" )
        print( f"\nSecurity Assessment Areas:" )
        print( f"  - Connection Security Analysis" )
        print( f"  - Configuration Audit" )
        print( f"  - Schema Security Review" )
        print( f"  - Sensitive Data Classification" )
        print( f"  - Vulnerability Assessment" )
        print( f"  - Compliance Checking (GDPR, PCI-DSS, HIPAA)" )
        print( f"{'='*60}" )

# Print application banner
def ShowBanner():
    print( f"\n{'='*60}" )
    print( f"DATABASE SECURITY AUDITOR" )
    print( f"{'='*60}" )
    print( f"Comprehensive Database Security Assessment Tool" )
    print( f"Author: Andrew Piggot" )
    print( f"Purpose: Educational and authorized security auditing" )
    print( f"{'='*60}" )

# Main application function
def Main():
    ShowBanner()
    auditor = DBTool()
    last_results = None
    
    print( "Welcome to the Database Security Auditor!" )
    print( "Type 'help' for usage information or 'quit' to exit.\n" )
    
    while True:
        try:
            user_input = input( "db-auditor> " ).strip()
            
            if not user_input:
                continue
            
            command_parts = user_input.split()
            command = command_parts[0].lower()
            
            if command in ['quit', 'exit', 'q']:
                print( "Thank you for using Database Security Auditor! Stay secure!" )
                break
            elif command == 'help':
                auditor.ShowHelp()
            
            elif command == 'audit':
                if len( command_parts ) < 3:
                    print( "Usage: audit <database_type> <file_path_or_connection_string>" )
                    print( "Example: audit sqlite sample_database.db" )
                    continue
                
                db_type = command_parts[1].lower()
                target = ' '.join( command_parts[2:] )
                
                if db_type == 'sqlite':
                    results = auditor.Audit( db_type, file_path=target )
                else:
                    results = auditor.Audit( db_type, connection_string=target )
                
                auditor.ShowResults( results )
                last_results = results
            
            elif command == 'test':
                if len( command_parts ) < 3:
                    print( "Usage: test <database_type> <file_path_or_connection_string>" )
                    print( "Example: test sqlite my_database.db" )
                    continue
                
                db_type = command_parts[1].lower()
                target = ' '.join( command_parts[2:] )
                
                if db_type == 'sqlite':
                    results = auditor.TestConn( db_type, file_path=target )
                else:
                    results = auditor.TestConn( db_type, connection_string=target )
                
                print( f"\n[CONNECTION] CONNECTION TEST RESULTS" )
                print( f"Database Type: {results['database_type']}" )
                print( f"Status: {results['connection_status']}" )
                if results['error']:
                    print( f"Error: {results['error']}" )
                if results['basic_info']:
                    print( f"Basic Info: {results['basic_info']}" )
            
            elif command == 'generate':
                if len( command_parts ) > 1 and command_parts[1].lower() == 'sample':
                    results = auditor.GenSample()
                    if results['status'] == 'success':
                        print( f"[SUCCESS] {results['message']}" )
                        print( f"Tables created: {', '.join( results['tables_created'] )}" )
                        print( f"Sample data: {results['sample_data']}" )
                    else:
                        print( f"[ERROR] {results['message']}" )
                else:
                    print( "Usage: generate sample" )
            
            elif command == 'export':
                if last_results and len( command_parts ) > 1:
                    filename = command_parts[1]
                    auditor.Export( last_results, filename )
                else:
                    print( "Usage: export <filename.json> (perform an audit first)" )
            
            else:
                print( f"Unknown command: {command}" )
                print( "Type 'help' for available commands" )
        
        except KeyboardInterrupt:
            print( "\n\nGoodbye! Stay secure!" )
            break
        except EOFError:
            print( "\nGoodbye! Stay secure!" )
            break
        except Exception as e:
            print( f"[ERROR] {str( e )}" )

if __name__ == "__main__":
    Main()
