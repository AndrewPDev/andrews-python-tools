"""
Hash Identifier Tool

Author:
Andrew Piggot

Purpose: 
Identify hash algorithms based on hash string characteristics

Usage: 
Pen testing, educational purposes only
"""

import re
import sys
from typing import List, Dict, Tuple

# Main class for identifying different hash algorithms
class HashTool:
    # Initialize the hash identifier with all supported patterns
    def __init__( self ):
        self.hash_patterns = {
            # MD5 - 32 hex characters
            'MD5': {
                'length': 32,
                'pattern': r'^[a-fA-F0-9]{32}$',
                'description': 'MD5 (Message Digest 5)',
                'example': '5d41402abc4b2a76b9719d911017c592'
            },
            
            # SHA-1 - 40 hex characters
            'SHA1': {
                'length': 40,
                'pattern': r'^[a-fA-F0-9]{40}$',
                'description': 'SHA-1 (Secure Hash Algorithm 1)',
                'example': 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
            },
            
            # SHA-224 - 56 hex characters
            'SHA224': {
                'length': 56,
                'pattern': r'^[a-fA-F0-9]{56}$',
                'description': 'SHA-224',
                'example': 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'
            },
            
            # SHA-256 - 64 hex characters
            'SHA256': {
                'length': 64,
                'pattern': r'^[a-fA-F0-9]{64}$',
                'description': 'SHA-256',
                'example': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            },
            
            # SHA-384 - 96 hex characters
            'SHA384': {
                'length': 96,
                'pattern': r'^[a-fA-F0-9]{96}$',
                'description': 'SHA-384',
                'example': '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'
            },
            
            # SHA-512 - 128 hex characters
            'SHA512': {
                'length': 128,
                'pattern': r'^[a-fA-F0-9]{128}$',
                'description': 'SHA-512',
                'example': 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
            },
            
            # bcrypt - starts with $2a$, $2b$, $2x$, $2y$ and has specific format
            'bcrypt': {
                'length': 60,
                'pattern': r'^\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$',
                'description': 'bcrypt',
                'example': '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
            },
            
            # scrypt - starts with $scrypt$
            'scrypt': {
                'length': None,  # Variable length
                'pattern': r'^\$scrypt\$',
                'description': 'scrypt',
                'example': '$scrypt$ln=16384,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjeMJWhFes5E'
            },
            
            # Argon2 - starts with $argon2
            'Argon2': {
                'length': None,  # Variable length
                'pattern': r'^\$argon2[id]?\$',
                'description': 'Argon2',
                'example': '$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A'
            },
            
            # PBKDF2 - starts with $pbkdf2
            'PBKDF2': {
                'length': None,  # Variable length
                'pattern': r'^\$pbkdf2',
                'description': 'PBKDF2',
                'example': '$pbkdf2$10000$8Ry2YIIo$Ak4rZhiLccKVbXwh2vBAz1uc'
            },
            
            # LM Hash - 32 hex characters (similar to MD5 but different context)
            'LM': {
                'length': 32,
                'pattern': r'^[a-fA-F0-9]{32}$',
                'description': 'LM Hash (LAN Manager)',
                'example': 'aad3b435b51404eeaad3b435b51404ee'
            },
            
            # NTLM Hash - 32 hex characters
            'NTLM': {
                'length': 32,
                'pattern': r'^[a-fA-F0-9]{32}$',
                'description': 'NTLM Hash',
                'example': 'b4b9b02e6f09a9bd760f388b67351e2b'
            },
            
            # MySQL5 - starts with *
            'MySQL5': {
                'length': 41,
                'pattern': r'^\*[a-fA-F0-9]{40}$',
                'description': 'MySQL5 Hash',
                'example': '*23AE809DDACAF96AF0FD78ED04B6A265E05AA257'
            },
            
            # WordPress - starts with $P$
            'WordPress': {
                'length': 34,
                'pattern': r'^\$P\$[./0-9A-Za-z]{31}$',
                'description': 'WordPress Hash',
                'example': '$P$B.lsj0yQQnRQr6rEvUhX2Tt6eBDwY/1'
            },
            
            # Drupal 7 - starts with $S$
            'Drupal7': {
                'length': 55,
                'pattern': r'^\$S\$[./0-9A-Za-z]{52}$',
                'description': 'Drupal 7 Hash',
                'example': '$S$C6VsIqiONKfFsA/HRm8ej/JQzAeM.Dotkb1X.fOsVPh4rP7D9K.6'
            },
            
            # Joomla - starts with {hash}:
            'Joomla': {
                'length': None,  # Variable
                'pattern': r'^[a-fA-F0-9]{32}:[a-zA-Z0-9./+]+$',
                'description': 'Joomla Hash',
                'example': '2d2d2c2d2d2d2d2d2d2d2d2d2d2d2d2d:salt'
            }
        }
    
    # Identify possible hash algorithms for the given hash string
    # Returns a list of possible matches with confidence scores
    def Identify( self, hash_string: str ) -> List[Dict[str, str]]:
        hash_string = hash_string.strip()
        matches = []
        
        for hash_type, properties in self.hash_patterns.items():
            if self._MatchPattern( hash_string, properties ):
                confidence = self._CalcConfidence( hash_string, properties )
                matches.append( {
                    'type': hash_type,
                    'description': properties['description'],
                    'confidence': confidence,
                    'example': properties['example']
                } )
        
        # Sort by confidence (highest first)
        matches.sort( key=lambda x: x['confidence'], reverse=True )
        return matches
    
    # Check if hash string matches the pattern for a specific hash type
    def _MatchPattern( self, hash_string: str, properties: Dict ) -> bool:
        pattern = properties['pattern']
        length = properties['length']
        
        # Check length if specified
        if length and len( hash_string ) != length:
            return False
        
        # Check pattern
        return bool( re.match( pattern, hash_string ) )
    
    # Calculate confidence score for hash identification
    def _CalcConfidence( self, hash_string: str, properties: Dict ) -> int:
        confidence = 0
        
        # Base confidence for pattern match
        confidence += 50
        
        # Length match bonus
        if properties['length'] and len( hash_string ) == properties['length']:
            confidence += 30
        
        # Specific pattern bonuses
        if hash_string.startswith( ( '$2a$', '$2b$', '$2x$', '$2y$' ) ):
            confidence += 20  # bcrypt is very distinctive
        elif hash_string.startswith( '*' ):
            confidence += 20  # MySQL5 is distinctive
        elif hash_string.startswith( '$P$' ):
            confidence += 20  # WordPress is distinctive
        elif hash_string.startswith( '$S$' ):
            confidence += 20  # Drupal7 is distinctive
        elif hash_string.startswith( '$argon2' ):
            confidence += 20  # Argon2 is distinctive
        elif hash_string.startswith( '$scrypt' ):
            confidence += 20  # scrypt is distinctive
        elif hash_string.startswith( '$pbkdf2' ):
            confidence += 20  # PBKDF2 is distinctive
        elif ':' in hash_string:
            confidence += 10  # Salted hashes
        
        return min( confidence, 100 )  # Cap at 100%
    
    # Analyze a file containing multiple hashes
    def AnalyzeFile( self, filename: str ) -> Dict[str, List[Dict]]:
        results = {}
        try:
            with open( filename, 'r', encoding='utf-8' ) as file:
                for line_num, line in enumerate( file, 1 ):
                    line = line.strip()
                    if line and not line.startswith( '#' ):  # Skip empty lines and comments
                        matches = self.Identify( line )
                        results[f"Line {line_num}: {line[:50]}..."] = matches
        except FileNotFoundError:
            print( f"Error: File '{filename}' not found." )
        except Exception as e:
            print( f"Error reading file: {e}" )
        
        return results
    
    # Print formatted results
    def ShowResults( self, matches: List[Dict[str, str]], hash_string: str ):
        print( f"\n{'='*60}" )
        print( f"Hash Analysis for: {hash_string}" )
        print( f"{'='*60}" )
        
        if not matches:
            print( "No matching hash patterns found!" )
            print( "\nThis could be:" )
            print( "- A custom hash format" )
            print( "- An encoded string (Base64, etc.)" )
            print( "- A corrupted hash" )
            print( "- An unsupported hash algorithm" )
            return
        
        print( f"\nFound {len( matches )} possible match(es):\n" )
        
        for i, match in enumerate( matches, 1 ):
            print( f"{i}. {match['type']} - {match['description']}" )
            print( f"   Confidence: {match['confidence']}%" )
            print( f"   Example: {match['example']}" )
            print()
        
        # Additional analysis
        self._ShowAnalysis( hash_string, matches )
    
    # Print additional analysis information
    def _ShowAnalysis( self, hash_string: str, matches: List[Dict] ):
        print( "Additional Analysis:" )
        print( f"   Length: {len( hash_string )} characters" )
        print( f"   Character set: {self._AnalyzeCharset( hash_string )}" )
        
        if matches:
            best_match = matches[0]
            print( f"   Most likely: {best_match['type']} ({best_match['confidence']}%)" )
            
            # Security recommendations
            if best_match['type'] in ['MD5', 'SHA1']:
                print( "   WARNING: This appears to be a weak hash algorithm!" )
            elif best_match['type'] in ['bcrypt', 'scrypt', 'Argon2', 'PBKDF2']:
                print( "   This appears to be a strong password hashing algorithm." )
    
    # Analyze the character set used in the hash
    def _AnalyzeCharset( self, hash_string: str ) -> str:
        if re.match( r'^[a-fA-F0-9]+$', hash_string ):
            return "Hexadecimal (0-9, a-f)"
        elif re.match( r'^[A-Za-z0-9+/=]+$', hash_string ):
            return "Base64-like (A-Z, a-z, 0-9, +, /, =)"
        elif re.match( r'^[A-Za-z0-9./]+$', hash_string ):
            return "Base64 variant (A-Z, a-z, 0-9, ., /)"
        else:
            return "Mixed/Special characters"

# Print application banner
def ShowBanner():
    banner = """
    ==============================================================
                         Hash Identifier                       
                      Author: Andrew Piggot                
    ==============================================================
    """
    print( banner )

# Print help information
def ShowHelp():
    help_text = """
    Usage:
    1. Single hash identification: Enter a hash string when prompted
    2. File analysis: Enter 'file:filename.txt' to analyze multiple hashes
    3. Help: Enter 'help' for this information
    4. Exit: Enter 'quit' or 'exit' to close the program
    
    Supported Hash Types:
    - MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
    - bcrypt, scrypt, Argon2, PBKDF2
    - NTLM, LM Hash
    - MySQL5, WordPress, Drupal 7, Joomla
    
    Examples:
    MD5:     5d41402abc4b2a76b9719d911017c592
    SHA-1:   aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
    bcrypt:  $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
    """
    print( help_text )

# Main application function
def main():
    ShowBanner()
    identifier = HashTool()
    
    print( "Welcome to the Hash Identifier Tool!" )
    print( "Type 'help' for usage information or 'quit' to exit.\n" )
    
    while True:
        try:
            user_input = input( "Enter hash to identify (or command): " ).strip()
            
            if not user_input:
                continue
            
            # Handle commands
            if user_input.lower() in ['quit', 'exit', 'q']:
                print( "Goodbye! Stay secure!" )
                break
            elif user_input.lower() == 'help':
                ShowHelp()
                continue
            elif user_input.lower().startswith( 'file:' ):
                # File analysis mode
                filename = user_input[5:].strip()
                print( f"\nAnalyzing file: {filename}" )
                results = identifier.AnalyzeFile( filename )
                
                if results:
                    for hash_info, matches in results.items():
                        print( f"\n{hash_info}" )
                        if matches:
                            best_match = matches[0]
                            print( f"   -> {best_match['type']} ({best_match['confidence']}%)" )
                        else:
                            print( "   -> No matches found" )
                continue
            
            # Single hash identification
            matches = identifier.Identify( user_input )
            identifier.ShowResults( matches, user_input )
            
        except KeyboardInterrupt:
            print( "\n\nGoodbye! Stay secure!" )
            break
        except Exception as e:
            print( f"Error: {e}" )

if __name__ == "__main__":
    main()