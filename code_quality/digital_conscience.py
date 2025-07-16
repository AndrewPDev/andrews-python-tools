"""
Digital Conscience

Author:
Andrew Piggot

Purpose: 
Monitor coding practices and provide feedback with personality-driven guidance

Usage: 
Code review, educational feedback, development best practices enforcement
"""

import os
import re
import sys
import time
import json
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

# Main class for monitoring and analyzing code quality
class ConscienceTool:
    
    def __init__( self ):
        self.personality = 'mentor'  # Default mode
        self.severity_level = 'medium'
        self.check_history = []
        self.violations = []
        self.scan_results = {}
        
        # Personality configurations
        self.personalities = {
            'mentor': {
                'name': 'Stern Mentor',
                'tone': 'constructive',
                'prefix': 'Remember',
                'advice_style': 'educational'
            },
            'intern': {
                'name': 'Passive-Aggressive Intern',
                'tone': 'sarcastic',
                'prefix': 'Oh, I see',
                'advice_style': 'snarky'
            },
            'coach': {
                'name': 'Supportive Coach',
                'tone': 'encouraging',
                'prefix': 'Hey there',
                'advice_style': 'motivational'
            }
        }
        
        # Code quality rules and patterns
        self.code_rules = {
            'empty_except': {
                'pattern': r'except[^:]*:\s*pass',
                'severity': 'high',
                'description': 'Empty except block with pass',
                'category': 'error_handling'
            },
            'empty_try': {
                'pattern': r'try:\s*pass',
                'severity': 'high',
                'description': 'Empty try block',
                'category': 'error_handling'
            },
            'bare_except': {
                'pattern': r'except:\s*',
                'severity': 'medium',
                'description': 'Bare except clause',
                'category': 'error_handling'
            },
            'print_debug': {
                'pattern': r'print\s*\(\s*["\'].*debug.*["\']',
                'severity': 'low',
                'description': 'Debug print statements',
                'category': 'debugging'
            },
            'todo_fixme': {
                'pattern': r'#\s*(TODO|FIXME|HACK)',
                'severity': 'low',
                'description': 'TODO/FIXME comments',
                'category': 'maintenance'
            },
            'long_line': {
                'pattern': r'.{121,}',
                'severity': 'low',
                'description': 'Line too long (>120 chars)',
                'category': 'style'
            },
            'no_docstring': {
                'pattern': r'^(def|class)\s+\w+.*:\s*$',
                'severity': 'medium',
                'description': 'Missing docstring',
                'category': 'documentation'
            },
            'hardcoded_path': {
                'pattern': r'["\'](?:[C-Z]:\\|/home/|/usr/)',
                'severity': 'medium',
                'description': 'Hardcoded file paths',
                'category': 'portability'
            },
            'sql_injection': {
                'pattern': r'execute\s*\(\s*["\'].*%.*["\']',
                'severity': 'high',
                'description': 'Potential SQL injection',
                'category': 'security'
            }
        }
        
        # Git commit rules
        self.git_rules = {
            'no_tests': {
                'description': 'Committing without running tests',
                'severity': 'high',
                'category': 'testing'
            },
            'large_commit': {
                'description': 'Commit touches too many files',
                'severity': 'medium',
                'category': 'maintainability'
            },
            'poor_message': {
                'description': 'Commit message too short or vague',
                'severity': 'medium',
                'category': 'documentation'
            },
            'direct_to_main': {
                'description': 'Committing directly to main/master',
                'severity': 'high',
                'category': 'workflow'
            }
        }
    
    # Set personality mode
    def SetMode( self, personality: str, severity: str = 'medium' ):
        if personality not in self.personalities:
            return {'error': f'Unknown personality: {personality}'}
        
        self.personality = personality
        self.severity_level = severity
        
        mode_info = self.personalities[personality]
        return {
            'status': 'success',
            'personality': mode_info['name'],
            'tone': mode_info['tone'],
            'severity': severity
        }
    
    # Scan a single file for code issues
    def ScanFile( self, file_path: str ) -> Dict:
        if not os.path.exists( file_path ):
            return {'error': f'File not found: {file_path}'}
        
        if not file_path.endswith( ('.py', '.js', '.ts', '.java', '.cpp', '.c') ):
            return {'error': 'Unsupported file type'}
        
        print( f"Scanning: {file_path}" )
        
        try:
            with open( file_path, 'r', encoding='utf-8' ) as f:
                content = f.read()
                lines = content.split( '\n' )
            
            violations = []
            
            for line_num, line in enumerate( lines, 1 ):
                line_violations = self._CheckLine( line, line_num )
                violations.extend( line_violations )
            
            # Additional file-level checks
            file_violations = self._CheckFile( content, file_path )
            violations.extend( file_violations )
            
            result = {
                'file': file_path,
                'violations': violations,
                'total_issues': len( violations ),
                'severity_breakdown': self._GetSeverityBreakdown( violations ),
                'scan_time': datetime.now().isoformat()
            }
            
            self.scan_results[file_path] = result
            
            if violations:
                self._DeliverFeedback( violations, file_path )
            
            return result
            
        except Exception as e:
            return {'error': f'Scan failed: {str( e )}'}
    
    # Check a single line for violations
    def _CheckLine( self, line: str, line_num: int ) -> List[Dict]:
        violations = []
        
        for rule_name, rule in self.code_rules.items():
            if re.search( rule['pattern'], line, re.IGNORECASE ):
                violations.append( {
                    'rule': rule_name,
                    'line': line_num,
                    'content': line.strip(),
                    'description': rule['description'],
                    'severity': rule['severity'],
                    'category': rule['category']
                } )
        
        return violations
    
    # Check entire file for violations
    def _CheckFile( self, content: str, file_path: str ) -> List[Dict]:
        violations = []
        
        # Check for missing docstrings in functions/classes
        functions = re.finditer( r'^(def|class)\s+(\w+).*?:', content, re.MULTILINE )
        for match in functions:
            start_pos = match.end()
            # Look for docstring after function definition
            next_lines = content[start_pos:start_pos + 200]
            if not re.search( r'^\s*["\']', next_lines, re.MULTILINE ):
                line_num = content[:match.start()].count( '\n' ) + 1
                violations.append( {
                    'rule': 'no_docstring',
                    'line': line_num,
                    'content': match.group( 0 ),
                    'description': f'Function/class {match.group( 2 )} missing docstring',
                    'severity': 'medium',
                    'category': 'documentation'
                } )
        
        return violations
    
    # Check git repository status
    def CheckGit( self, repo_path: str = '.' ) -> Dict:
        if not os.path.exists( os.path.join( repo_path, '.git' ) ):
            return {'error': 'Not a git repository'}
        
        violations = []
        
        try:
            # Check if there are uncommitted changes
            result = subprocess.run( 
                ['git', 'status', '--porcelain'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True 
            )
            
            if result.stdout.strip():
                violations.append( {
                    'rule': 'uncommitted_changes',
                    'description': 'Uncommitted changes detected',
                    'severity': 'low',
                    'category': 'workflow'
                } )
            
            # Check current branch
            result = subprocess.run( 
                ['git', 'branch', '--show-current'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True 
            )
            
            current_branch = result.stdout.strip()
            if current_branch in ['main', 'master']:
                violations.append( {
                    'rule': 'direct_to_main',
                    'description': f'Working directly on {current_branch} branch',
                    'severity': 'high',
                    'category': 'workflow'
                } )
            
            # Check recent commits
            result = subprocess.run( 
                ['git', 'log', '--oneline', '-5'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True 
            )
            
            if result.stdout:
                commits = result.stdout.strip().split( '\n' )
                for commit in commits:
                    message = commit.split( ' ', 1 )[1] if ' ' in commit else ''
                    if len( message ) < 10:
                        violations.append( {
                            'rule': 'poor_message',
                            'description': f'Short commit message: "{message}"',
                            'severity': 'medium',
                            'category': 'documentation'
                        } )
            
            # Check for test files
            test_files = []
            for root, dirs, files in os.walk( repo_path ):
                for file in files:
                    if 'test' in file.lower() and file.endswith( '.py' ):
                        test_files.append( file )
            
            if not test_files:
                violations.append( {
                    'rule': 'no_tests',
                    'description': 'No test files found in repository',
                    'severity': 'high',
                    'category': 'testing'
                } )
            
            git_result = {
                'repository': repo_path,
                'current_branch': current_branch,
                'violations': violations,
                'total_issues': len( violations ),
                'test_files_found': len( test_files )
            }
            
            if violations:
                self._DeliverGitFeedback( violations )
            
            return git_result
            
        except subprocess.CalledProcessError as e:
            return {'error': f'Git command failed: {e}'}
        except Exception as e:
            return {'error': f'Git check failed: {str( e )}'}
    
    # Scan entire directory
    def ScanDir( self, directory: str ) -> Dict:
        if not os.path.exists( directory ):
            return {'error': f'Directory not found: {directory}'}
        
        print( f"Scanning directory: {directory}" )
        
        all_violations = []
        scanned_files = []
        
        for root, dirs, files in os.walk( directory ):
            # Skip common ignore directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', '.venv']]
            
            for file in files:
                if file.endswith( ('.py', '.js', '.ts', '.java', '.cpp', '.c') ):
                    file_path = os.path.join( root, file )
                    result = self.ScanFile( file_path )
                    
                    if 'violations' in result:
                        all_violations.extend( result['violations'] )
                        scanned_files.append( file_path )
        
        directory_result = {
            'directory': directory,
            'files_scanned': len( scanned_files ),
            'total_violations': len( all_violations ),
            'severity_breakdown': self._GetSeverityBreakdown( all_violations ),
            'scan_time': datetime.now().isoformat()
        }
        
        return directory_result
    
    # Get severity breakdown
    def _GetSeverityBreakdown( self, violations: List[Dict] ) -> Dict:
        breakdown = {'high': 0, 'medium': 0, 'low': 0}
        
        for violation in violations:
            severity = violation.get( 'severity', 'low' )
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    # Deliver feedback based on personality
    def _DeliverFeedback( self, violations: List[Dict], file_path: str ):
        personality = self.personalities[self.personality]
        
        print( f"\n{personality['prefix']}, I found some issues in {file_path}:" )
        
        for violation in violations:
            message = self._GetPersonalizedMessage( violation, personality )
            severity_marker = self._GetSeverityMarker( violation['severity'] )
            
            print( f"  {severity_marker} Line {violation['line']}: {message}" )
            if violation.get( 'content' ):
                print( f"    Code: {violation['content']}" )
    
    # Deliver git-specific feedback
    def _DeliverGitFeedback( self, violations: List[Dict] ):
        personality = self.personalities[self.personality]
        
        print( f"\n{personality['prefix']}, I noticed some git workflow issues:" )
        
        for violation in violations:
            message = self._GetGitMessage( violation, personality )
            severity_marker = self._GetSeverityMarker( violation['severity'] )
            
            print( f"  {severity_marker} {message}" )
    
    # Get personalized message based on personality
    def _GetPersonalizedMessage( self, violation: Dict, personality: Dict ) -> str:
        rule = violation['rule']
        description = violation['description']
        
        if personality['tone'] == 'constructive':
            messages = {
                'empty_except': f"{description}. Consider logging the exception or handling it properly.",
                'empty_try': f"{description}. Empty try blocks serve no purpose.",
                'bare_except': f"{description}. Catch specific exceptions instead.",
                'print_debug': f"{description}. Use logging instead of print for debugging.",
                'todo_fixme': f"{description}. Consider addressing these before committing.",
                'long_line': f"{description}. Break it up for better readability.",
                'no_docstring': f"{description}. Document your code for future you.",
                'hardcoded_path': f"{description}. Use relative paths or configuration.",
                'sql_injection': f"{description}. Use parameterized queries!"
            }
        
        elif personality['tone'] == 'sarcastic':
            messages = {
                'empty_except': f"Nice empty except block. I'm sure nothing could go wrong.",
                'empty_try': f"An empty try block. Bold strategy, let's see how it works out.",
                'bare_except': f"Catching ALL exceptions. What could possibly go wrong?",
                'print_debug': f"Debug prints in production code. Classic.",
                'todo_fixme': f"More TODOs. I'll add them to the never-ending list.",
                'long_line': f"Line longer than a CVS receipt. Ever heard of readability?",
                'no_docstring': f"No documentation. Future you will love this mystery code.",
                'hardcoded_path': f"Hardcoded paths. Works on my machine, right?",
                'sql_injection': f"Potential SQL injection. Hackers will send thank-you cards."
            }
        
        else:  # encouraging
            messages = {
                'empty_except': f"{description}. You're doing great! Just add some error handling.",
                'empty_try': f"{description}. Almost there! Add some code in that try block.",
                'bare_except': f"{description}. Good error handling! Make it more specific.",
                'print_debug': f"{description}. Debug prints show you're testing! Try logging next.",
                'todo_fixme': f"{description}. Great that you're planning improvements!",
                'long_line': f"{description}. Break it up and it'll be perfect!",
                'no_docstring': f"{description}. Add some docs and this will be awesome!",
                'hardcoded_path': f"{description}. Make it portable and you're golden!",
                'sql_injection': f"{description}. Security first! Use parameterized queries."
            }
        
        return messages.get( rule, description )
    
    # Get git-specific messages
    def _GetGitMessage( self, violation: Dict, personality: Dict ) -> str:
        rule = violation['rule']
        description = violation['description']
        
        if personality['tone'] == 'constructive':
            messages = {
                'uncommitted_changes': "You have uncommitted changes. Consider committing or stashing them.",
                'direct_to_main': "Working directly on main branch. Consider using feature branches.",
                'poor_message': f"{description}. Write descriptive commit messages.",
                'no_tests': "No test files found. Consider adding tests for your code."
            }
        elif personality['tone'] == 'sarcastic':
            messages = {
                'uncommitted_changes': "Uncommitted changes hanging around like yesterday's laundry.",
                'direct_to_main': "Committing to main. Living dangerously, I see.",
                'poor_message': f"{description}. Shakespeare would weep.",
                'no_tests': "No tests. Hope your code is perfect on the first try."
            }
        else:  # encouraging
            messages = {
                'uncommitted_changes': "Just a reminder about those uncommitted changes!",
                'direct_to_main': "Consider feature branches for safer development!",
                'poor_message': f"{description}. A bit more detail would be helpful!",
                'no_tests': "Adding tests would make your code even better!"
            }
        
        return messages.get( rule, description )
    
    # Get severity marker
    def _GetSeverityMarker( self, severity: str ) -> str:
        markers = {
            'high': '[!]',
            'medium': '[*]',
            'low': '[-]'
        }
        return markers.get( severity, '[-]' )
    
    # Generate comprehensive report
    def GenReport( self ) -> Dict:
        if not self.scan_results:
            return {'error': 'No scan results available'}
        
        total_files = len( self.scan_results )
        total_violations = sum( len( result['violations'] ) for result in self.scan_results.values() )
        
        # Category breakdown
        categories = {}
        severity_totals = {'high': 0, 'medium': 0, 'low': 0}
        
        for result in self.scan_results.values():
            for violation in result['violations']:
                category = violation['category']
                severity = violation['severity']
                
                categories[category] = categories.get( category, 0 ) + 1
                severity_totals[severity] += 1
        
        # Calculate quality score (0-10)
        score = 10
        score -= min( severity_totals['high'] * 2, 6 )
        score -= min( severity_totals['medium'] * 1, 3 )
        score -= min( severity_totals['low'] * 0.1, 1 )
        score = max( 0, round( score, 1 ) )
        
        report = {
            'summary': {
                'files_scanned': total_files,
                'total_violations': total_violations,
                'quality_score': score,
                'scan_date': datetime.now().isoformat()
            },
            'severity_breakdown': severity_totals,
            'category_breakdown': categories,
            'personality_mode': self.personality,
            'detailed_results': self.scan_results
        }
        
        return report
    
    # Show comprehensive report
    def ShowReport( self ):
        report = self.GenReport()
        
        if 'error' in report:
            print( f"Error: {report['error']}" )
            return
        
        summary = report['summary']
        
        print( f"\n{'='*60}" )
        print( f"DIGITAL CONSCIENCE REPORT" )
        print( f"{'='*60}" )
        print( f"Files Scanned: {summary['files_scanned']}" )
        print( f"Total Issues: {summary['total_violations']}" )
        print( f"Quality Score: {summary['quality_score']}/10 {self._GetScoreRating( summary['quality_score'] )}" )
        print( f"Personality Mode: {self.personalities[self.personality]['name']}" )
        
        print( f"\nSEVERITY BREAKDOWN" )
        severity = report['severity_breakdown']
        print( f"  High Priority:   {severity['high']}" )
        print( f"  Medium Priority: {severity['medium']}" )
        print( f"  Low Priority:    {severity['low']}" )
        
        if report['category_breakdown']:
            print( f"\nISSUE CATEGORIES" )
            for category, count in sorted( report['category_breakdown'].items() ):
                print( f"  {category.title()}: {count}" )
        
        # Show top violations
        all_violations = []
        for result in self.scan_results.values():
            all_violations.extend( result['violations'] )
        
        high_priority = [v for v in all_violations if v['severity'] == 'high']
        if high_priority:
            print( f"\nHIGH PRIORITY ISSUES" )
            for violation in high_priority[:5]:  # Show top 5
                print( f"  {violation['description']} - Line {violation['line']}" )
        
        print( f"\n{'='*60}" )
    
    # Get score rating
    def _GetScoreRating( self, score: float ) -> str:
        if score >= 8:
            return "(Excellent)"
        elif score >= 6:
            return "(Good)"
        elif score >= 4:
            return "(Needs Work)"
        else:
            return "(Critical Issues)"
    
    # Export report to JSON
    def Export( self, filename: str ):
        report = self.GenReport()
        
        try:
            with open( filename, 'w' ) as f:
                json.dump( report, f, indent=2, default=str )
            print( f"Report exported to: {filename}" )
        except Exception as e:
            print( f"Export failed: {e}" )
    
    # Show available personalities
    def ShowModes( self ):
        print( f"\n{'='*60}" )
        print( f"AVAILABLE PERSONALITY MODES" )
        print( f"{'='*60}" )
        
        for key, personality in self.personalities.items():
            print( f"\n{key.upper()}: {personality['name']}" )
            print( f"  Tone: {personality['tone']}" )
            print( f"  Style: {personality['advice_style']}" )
    
    # Show help information
    def ShowHelp( self ):
        print( f"\n{'='*60}" )
        print( f"DIGITAL CONSCIENCE - HELP" )
        print( f"{'='*60}" )
        print( f"Commands:" )
        print( f"  scan <file>           - Scan a single file" )
        print( f"  scandir <directory>   - Scan entire directory" )
        print( f"  git [path]            - Check git repository status" )
        print( f"  mode <personality>    - Set personality mode" )
        print( f"  modes                 - Show available personalities" )
        print( f"  report                - Show comprehensive report" )
        print( f"  export <filename>     - Export report to JSON" )
        print( f"  help                  - Show this help" )
        print( f"  quit                  - Exit program" )
        print( f"\nPersonalities: mentor, intern, coach" )
        print( f"\nExamples:" )
        print( f"  scan myfile.py" )
        print( f"  scandir ./src" )
        print( f"  mode intern" )
        print( f"  git ." )

# Print application banner
def ShowBanner():
    banner = """
    ==============================================================
                        Digital Conscience                       
                       Author: Andrew Piggot                
    ==============================================================
    """
    print( banner )

# Main application function
def main():
    ShowBanner()
    conscience = ConscienceTool()
    
    print( "Welcome to your Digital Conscience!" )
    print( "I'll help you write better code with gentle reminders." )
    print( "Type 'help' for commands or 'modes' to see personality options.\n" )
    
    while True:
        try:
            user_input = input( "conscience> " ).strip()
            
            if not user_input:
                continue
            
            parts = user_input.split()
            command = parts[0].lower()
            
            if command in ['quit', 'exit', 'q']:
                print( "Keep writing great code! Remember, I'm always watching..." )
                break
            
            elif command == 'help':
                conscience.ShowHelp()
            
            elif command == 'modes':
                conscience.ShowModes()
            
            elif command == 'mode':
                if len( parts ) > 1:
                    result = conscience.SetMode( parts[1] )
                    if 'error' in result:
                        print( f"Error: {result['error']}" )
                    else:
                        print( f"Switched to: {result['personality']} ({result['tone']} tone)" )
                else:
                    print( "Usage: mode <personality>" )
            
            elif command == 'scan':
                if len( parts ) > 1:
                    file_path = ' '.join( parts[1:] )
                    result = conscience.ScanFile( file_path )
                    if 'error' in result:
                        print( f"Error: {result['error']}" )
                    else:
                        print( f"\nScan complete: {result['total_issues']} issues found" )
                else:
                    print( "Usage: scan <file_path>" )
            
            elif command == 'scandir':
                if len( parts ) > 1:
                    dir_path = ' '.join( parts[1:] )
                    result = conscience.ScanDir( dir_path )
                    if 'error' in result:
                        print( f"Error: {result['error']}" )
                    else:
                        print( f"\nDirectory scan complete:" )
                        print( f"  Files scanned: {result['files_scanned']}" )
                        print( f"  Total issues: {result['total_violations']}" )
                else:
                    print( "Usage: scandir <directory_path>" )
            
            elif command == 'git':
                repo_path = parts[1] if len( parts ) > 1 else '.'
                result = conscience.CheckGit( repo_path )
                if 'error' in result:
                    print( f"Error: {result['error']}" )
                else:
                    print( f"\nGit check complete:" )
                    print( f"  Current branch: {result['current_branch']}" )
                    print( f"  Issues found: {result['total_issues']}" )
                    print( f"  Test files: {result['test_files_found']}" )
            
            elif command == 'report':
                conscience.ShowReport()
            
            elif command == 'export':
                if len( parts ) > 1:
                    filename = parts[1]
                    conscience.Export( filename )
                else:
                    print( "Usage: export <filename>" )
            
            else:
                print( f"Unknown command: {command}" )
                print( "Type 'help' for available commands" )
        
        except KeyboardInterrupt:
            print( "\n\nGoodbye! Keep coding responsibly!" )
            break
        except EOFError:
            print( "\n\nGoodbye! Keep coding responsibly!" )
            break
        except Exception as e:
            print( f"Error: {e}" )

if __name__ == "__main__":
    main()
