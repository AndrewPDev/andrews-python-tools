#!/usr/bin/env python3
"""
Crypto Analyzer - Encryption/Decryption Tool

Author:
Andrew Piggot

Purpose: 
Multi-purpose encryption and decryption tool supporting various ciphers, file encryption, and steganography

Usage: 
Data protection, secure communication, educational cryptography, forensic analysis
"""

import os
import sys
import base64
import hashlib
import secrets
import string
from typing import Dict, List, Optional, Tuple, Any, Union
from datetime import datetime
from pathlib import Path
import json
import re

# Try to import cryptography library for advanced encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Try to import PIL for steganography
try:
    from PIL import Image
    import numpy as np
    STEGANOGRAPHY_AVAILABLE = True
except ImportError:
    STEGANOGRAPHY_AVAILABLE = False

# Main class for cryptographic operations and analysis
class CryptoTool:
    
    def __init__( self ):
        self.ciphers = [
            'caesar', 'vigenere', 'atbash', 'rot13', 'base64', 'hex',
            'aes', 'fernet', 'xor', 'substitution', 'morse', 'binary'
        ]
        self.results = {}
        self.file_ops = {}
        self.stego_results = {}
        self.script_dir = Path( __file__ ).parent.absolute()
        
        # Initialize cipher mappings
        self.morse = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/'
        }
        
        self.rev_morse = {v: k for k, v in self.morse.items()}
    
    # Main encryption function
    def Encrypt( self, plaintext: str, cipher_type: str, key: str = None, **kwargs ) -> Dict:
        """Encrypt data using specified cipher"""
        print( f"\nEncrypting data with {cipher_type.upper( )} cipher..." )
        
        try:
            if cipher_type.lower() == 'caesar':
                shift = int( key ) if key else 3
                return self._Caesar( plaintext, shift, encrypt=True )
            
            elif cipher_type.lower() == 'vigenere':
                if not key:
                    return {'error': 'Vigenere cipher requires a key'}
                return self._Vigenere( plaintext, key, encrypt=True )
            
            elif cipher_type.lower() == 'atbash':
                return self._Atbash( plaintext )
            
            elif cipher_type.lower() == 'rot13':
                return self._Rot13( plaintext )
            
            elif cipher_type.lower() == 'base64':
                return self._B64Encode( plaintext )
            
            elif cipher_type.lower() == 'hex':
                return self._HexEncode( plaintext )
            
            elif cipher_type.lower() == 'xor':
                if not key:
                    return {'error': 'XOR cipher requires a key'}
                return self._Xor( plaintext, key )
            
            elif cipher_type.lower() == 'morse':
                return self._MorseEncode( plaintext )
            
            elif cipher_type.lower() == 'binary':
                return self._BinEncode( plaintext )
            
            elif cipher_type.lower() == 'substitution':
                key_map = kwargs.get( 'substitution_key', None )
                return self._Subst( plaintext, key_map, encrypt=True )
            
            elif cipher_type.lower() == 'fernet':
                if not CRYPTO_AVAILABLE:
                    return {'error': 'Cryptography library not installed. Run: pip install cryptography'}
                return self._FernetEnc( plaintext, key )
            
            elif cipher_type.lower() == 'aes':
                if not CRYPTO_AVAILABLE:
                    return {'error': 'Cryptography library not installed. Run: pip install cryptography'}
                return self._AesEnc( plaintext, key )
            
            else:
                return {'error': f'Unsupported cipher type: {cipher_type}'}
                
        except Exception as e:
            return {'error': f'Encryption failed: {str( e )}'}
    
    # Main decryption function
    def Decrypt( self, ciphertext: str, cipher_type: str, key: str = None, **kwargs ) -> Dict:
        """Decrypt data using specified cipher"""
        print( f"\nDecrypting data with {cipher_type.upper( )} cipher..." )
        
        try:
            if cipher_type.lower() == 'caesar':
                shift = int( key ) if key else 3
                return self._Caesar( ciphertext, shift, encrypt=False )
            
            elif cipher_type.lower() == 'vigenere':
                if not key:
                    return {'error': 'Vigenere cipher requires a key'}
                return self._Vigenere( ciphertext, key, encrypt=False )
            
            elif cipher_type.lower() == 'atbash':
                return self._Atbash( ciphertext )
            
            elif cipher_type.lower() == 'rot13':
                return self._Rot13( ciphertext )
            
            elif cipher_type.lower() == 'base64':
                return self._B64Decode( ciphertext )
            
            elif cipher_type.lower() == 'hex':
                return self._HexDecode( ciphertext )
            
            elif cipher_type.lower() == 'xor':
                if not key:
                    return {'error': 'XOR cipher requires a key'}
                return self._Xor( ciphertext, key )
            
            elif cipher_type.lower() == 'morse':
                return self._MorseDecode( ciphertext )
            
            elif cipher_type.lower() == 'binary':
                return self._BinDecode( ciphertext )
            
            elif cipher_type.lower() == 'substitution':
                key_map = kwargs.get( 'substitution_key', None )
                return self._Subst( ciphertext, key_map, encrypt=False )
            
            elif cipher_type.lower() == 'fernet':
                if not CRYPTO_AVAILABLE:
                    return {'error': 'Cryptography library not installed. Run: pip install cryptography'}
                return self._FernetDec( ciphertext, key )
            
            elif cipher_type.lower() == 'aes':
                if not CRYPTO_AVAILABLE:
                    return {'error': 'Cryptography library not installed. Run: pip install cryptography'}
                return self._AesDec( ciphertext, key )
            
            else:
                return {'error': f'Unsupported cipher type: {cipher_type}'}
                
        except Exception as e:
            return {'error': f'Decryption failed: {str( e )}'}
    
    # Caesar cipher implementation
    def _Caesar( self, text: str, shift: int, encrypt: bool = True ) -> Dict:
        if not encrypt:
            shift = -shift
        
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted = ( ord( char ) - ascii_offset + shift ) % 26
                result += chr( shifted + ascii_offset )
            else:
                result += char
        
        return {
            'success': True,
            'cipher': 'Caesar',
            'key': abs( shift ),
            'input': text,
            'output': result,
            'operation': 'encryption' if encrypt else 'decryption'
        }
    
    # Vigenere cipher implementation
    def _Vigenere( self, text: str, key: str, encrypt: bool = True ) -> Dict:
        key = key.upper()
        key_repeated = ( key * ( len( text ) // len( key ) + 1 ) )[:len( text )]
        result = ""
        key_index = 0
        
        for char in text:
            if char.isalpha():
                shift = ord( key_repeated[key_index] ) - 65
                if not encrypt:
                    shift = -shift
                
                ascii_offset = 65 if char.isupper() else 97
                shifted = ( ord( char ) - ascii_offset + shift ) % 26
                result += chr( shifted + ascii_offset )
                key_index += 1
            else:
                result += char
        
        return {
            'success': True,
            'cipher': 'Vigenere',
            'key': key,
            'input': text,
            'output': result,
            'operation': 'encryption' if encrypt else 'decryption'
        }
    
    # Atbash cipher implementation
    def _Atbash( self, text: str ) -> Dict:
        result = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result += chr( 90 - (ord(char ) - 65))
                else:
                    result += chr( 122 - (ord(char ) - 97))
            else:
                result += char
        
        return {
            'success': True,
            'cipher': 'Atbash',
            'key': 'N/A (fixed mapping)',
            'input': text,
            'output': result,
            'operation': 'encryption/decryption'
        }
    
    # ROT13 cipher implementation
    def _Rot13( self, text: str ) -> Dict:
        return self._Caesar( text, 13, encrypt=True )
    
    # Base64 encoding
    def _B64Encode( self, text: str ) -> Dict:
        encoded = base64.b64encode( text.encode('utf-8' )).decode( 'utf-8' )
        return {
            'success': True,
            'cipher': 'Base64',
            'key': 'N/A (standard encoding)',
            'input': text,
            'output': encoded,
            'operation': 'encoding'
        }
    
    # Base64 decoding
    def _B64Decode( self, text: str ) -> Dict:
        try:
            decoded = base64.b64decode( text ).decode( 'utf-8' )
            return {
                'success': True,
                'cipher': 'Base64',
                'key': 'N/A (standard encoding)',
                'input': text,
                'output': decoded,
                'operation': 'decoding'
            }
        except Exception as e:
            return {'error': f'Invalid Base64 input: {str( e )}'}
    
    # Hexadecimal encoding
    def _HexEncode( self, text: str ) -> Dict:
        encoded = text.encode( 'utf-8' ).hex()
        return {
            'success': True,
            'cipher': 'Hexadecimal',
            'key': 'N/A (standard encoding)',
            'input': text,
            'output': encoded,
            'operation': 'encoding'
        }
    
    # Hexadecimal decoding
    def _HexDecode( self, text: str ) -> Dict:
        try:
            decoded = bytes.fromhex( text ).decode( 'utf-8' )
            return {
                'success': True,
                'cipher': 'Hexadecimal',
                'key': 'N/A (standard encoding)',
                'input': text,
                'output': decoded,
                'operation': 'decoding'
            }
        except Exception as e:
            return {'error': f'Invalid hexadecimal input: {str( e )}'}
    
    # XOR cipher implementation
    def _Xor( self, text: str, key: str ) -> Dict:
        key_bytes = key.encode( 'utf-8' )
        result = ""
        
        for i, char in enumerate( text ):
            key_char = key_bytes[i % len( key_bytes )]
            xor_result = ord( char ) ^ key_char
            result += chr( xor_result )
        
        return {
            'success': True,
            'cipher': 'XOR',
            'key': key,
            'input': text,
            'output': result,
            'operation': 'encryption/decryption'
        }
    
    # Morse code encoding
    def _MorseEncode( self, text: str ) -> Dict:
        morse_out = []
        for char in text.upper():
            if char in self.morse:
                morse_out.append( self.morse[char] )
            elif char == ' ':
                morse_out.append( '/' )
            else:
                morse_out.append( '?' )
        
        return {
            'success': True,
            'cipher': 'Morse Code',
            'key': 'N/A (standard mapping)',
            'input': text,
            'output': ' '.join( morse_out ),
            'operation': 'encoding'
        }
    
    # Morse code decoding
    def _MorseDecode( self, text: str ) -> Dict:
        morse_parts = text.split( ' ' )
        result = ""
        
        for part in morse_parts:
            if part in self.rev_morse:
                result += self.rev_morse[part]
            elif part == '/':
                result += ' '
            else:
                result += '?'
        
        return {
            'success': True,
            'cipher': 'Morse Code',
            'key': 'N/A (standard mapping)',
            'input': text,
            'output': result,
            'operation': 'decoding'
        }
    
    # Binary encoding
    def _BinEncode( self, text: str ) -> Dict:
        bin_result = ' '.join( format(ord(char ), '08b') for char in text)
        return {
            'success': True,
            'cipher': 'Binary',
            'key': 'N/A (standard encoding)',
            'input': text,
            'output': bin_result,
            'operation': 'encoding'
        }
    
    # Binary decoding
    def _BinDecode( self, text: str ) -> Dict:
        try:
            binary_parts = text.split()
            result = ''.join( chr(int(part, 2 )) for part in binary_parts)
            return {
                'success': True,
                'cipher': 'Binary',
                'key': 'N/A (standard encoding)',
                'input': text,
                'output': result,
                'operation': 'decoding'
            }
        except Exception as e:
            return {'error': f'Invalid binary input: {str( e )}'}
    
    # Substitution cipher implementation
    def _Subst( self, text: str, key_map: Dict = None, encrypt: bool = True ) -> Dict:
        if not key_map:
            # Generate random substitution key
            alphabet = string.ascii_uppercase
            shuffled = list( alphabet )
            secrets.SystemRandom().shuffle( shuffled )
            key_map = dict( zip(alphabet, shuffled ))
        
        if not encrypt:
            # Reverse the mapping for decryption
            key_map = {v: k for k, v in key_map.items()}
        
        result = ""
        for char in text:
            if char.upper() in key_map:
                new_char = key_map[char.upper()]
                result += new_char.lower() if char.islower() else new_char
            else:
                result += char
        
        return {
            'success': True,
            'cipher': 'Substitution',
            'key': key_map,
            'input': text,
            'output': result,
            'operation': 'encryption' if encrypt else 'decryption'
        }
    
    # Fernet encryption (requires cryptography library)
    def _FernetEnc( self, text: str, key: str = None ) -> Dict:
        try:
            if not key:
                # Generate new key
                fernet_key = Fernet.generate_key()
                key_str = base64.urlsafe_b64encode( fernet_key ).decode()
            else:
                # Use provided key
                fernet_key = base64.urlsafe_b64decode( key.encode( ))
                key_str = key
            
            fernet = Fernet( fernet_key )
            encrypted = fernet.encrypt( text.encode('utf-8' ))
            
            return {
                'success': True,
                'cipher': 'Fernet (AES 128)',
                'key': key_str,
                'input': text,
                'output': base64.urlsafe_b64encode( encrypted ).decode(),
                'operation': 'encryption'
            }
        except Exception as e:
            return {'error': f'Fernet encryption failed: {str( e )}'}
    
    # Fernet decryption
    def _FernetDec( self, ciphertext: str, key: str ) -> Dict:
        try:
            fernet_key = base64.urlsafe_b64decode( key.encode( ))
            fernet = Fernet( fernet_key )
            encrypted_data = base64.urlsafe_b64decode( ciphertext.encode( ))
            decrypted = fernet.decrypt( encrypted_data ).decode( 'utf-8' )
            
            return {
                'success': True,
                'cipher': 'Fernet (AES 128)',
                'key': key,
                'input': ciphertext,
                'output': decrypted,
                'operation': 'decryption'
            }
        except Exception as e:
            return {'error': f'Fernet decryption failed: {str( e )}'}
    
    # AES encryption (requires cryptography library)
    def _AesEnc( self, text: str, password: str = None ) -> Dict:
        try:
            if not password:
                password = self.GenPassword( 16 )
            
            # Generate salt and IV
            salt = secrets.token_bytes( 16 )
            iv = secrets.token_bytes( 16 )
            
            # Derive key from password
            kdf = PBKDF2HMAC( 
                algorithm=hashes.SHA256( ),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive( password.encode( ))
            
            # Encrypt the data
            cipher = Cipher( algorithms.AES(key ), modes.CBC( iv ))
            encryptor = cipher.encryptor()
            
            # Pad the text to multiple of 16 bytes
            pad_length = 16 - (len( text ) % 16)
            padded_text = text + (chr( pad_length ) * pad_length)
            
            encrypted = encryptor.update( padded_text.encode( )) + encryptor.finalize()
            
            # Combine salt + iv + encrypted data
            result = base64.b64encode( salt + iv + encrypted ).decode()
            
            return {
                'success': True,
                'cipher': 'AES-256-CBC',
                'key': password,
                'input': text,
                'output': result,
                'operation': 'encryption'
            }
        except Exception as e:
            return {'error': f'AES encryption failed: {str( e )}'}
    
    # AES decryption
    def _AesDec( self, ciphertext: str, password: str ) -> Dict:
        try:
            # Decode the base64 data
            data = base64.b64decode( ciphertext.encode( ))
            
            # Extract salt, IV, and encrypted data
            salt = data[:16]
            iv = data[16:32]
            encrypted = data[32:]
            
            # Derive key from password
            kdf = PBKDF2HMAC( 
                algorithm=hashes.SHA256( ),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive( password.encode( ))
            
            # Decrypt the data
            cipher = Cipher( algorithms.AES(key ), modes.CBC( iv ))
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update( encrypted ) + decryptor.finalize()
            
            # Remove padding
            pad_length = decrypted_padded[-1]
            decrypted = decrypted_padded[:-pad_length].decode()
            
            return {
                'success': True,
                'cipher': 'AES-256-CBC',
                'key': password,
                'input': ciphertext,
                'output': decrypted,
                'operation': 'decryption'
            }
        except Exception as e:
            return {'error': f'AES decryption failed: {str( e )}'}
    
    # Brute force Caesar cipher
    def BruteForce( self, ciphertext: str ) -> Dict:
        print( "\nBrute forcing Caesar cipher..." )
        
        results = []
        for shift in range( 26 ):
            result = self._Caesar( ciphertext, shift, encrypt=False )
            if result.get( 'success' ):
                results.append( {
                    'shift': shift,
                    'decrypted': result['output'],
                    'readable_score': self._CalcScore(result['output'] )
                })
        
        # Sort by readability score
        results.sort( key=lambda x: x['readable_score'], reverse=True )
        
        return {
            'success': True,
            'cipher': 'Caesar Brute Force',
            'input': ciphertext,
            'results': results[:5],  # Top 5 most likely results
            'operation': 'brute_force'
        }
    
    # Calculate readability score for brute force attempts
    def _CalcScore( self, text: str ) -> float:
        if not text:
            return 0
        
        score = 0
        text_upper = text.upper()
        
        # Common English letter frequencies
        common_letters = {'E': 12.02, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 6.97, 'N': 6.75}
        
        # Check for common English words
        common_words = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'HAD', 'BY']
        for word in common_words:
            score += text_upper.count( word ) * 2
        
        # Check letter frequency
        for letter, expected_freq in common_letters.items():
            actual_freq = (text_upper.count( letter ) / len( text )) * 100
            score += max( 0, 5 - abs(actual_freq - expected_freq ))
        
        # Penalty for too many non-alphabetic characters
        alpha_ratio = sum( 1 for c in text if c.isalpha( )) / len( text )
        score *= alpha_ratio
        
        return score
    
    # File encryption
    def EncFile( self, file_path: str, output_path: str = None, cipher_type: str = 'fernet', password: str = None ) -> Dict:
        print( f"\nEncrypting file: {file_path}" )
        
        if not CRYPTO_AVAILABLE and cipher_type in ['fernet', 'aes']:
            return {'error': 'Cryptography library not installed. Run: pip install cryptography'}
        
        # Convert relative paths to absolute paths
        if not os.path.isabs( file_path ):
            file_path = os.path.join( self.script_dir, file_path )
        
        if not os.path.exists( file_path ):
            return {'error': f'File not found: {file_path}'}
        
        try:
            # Read file content
            with open( file_path, 'rb' ) as file:
                file_data = file.read()
            
            # Convert to string for encryption
            file_content = base64.b64encode( file_data ).decode( 'utf-8' )
            
            # Encrypt the content
            encryption_result = self.Encrypt( file_content, cipher_type, password )
            
            if 'error' in encryption_result:
                return encryption_result
            
            # Determine output path
            if not output_path:
                output_path = f"{file_path}.encrypted"
            
            # Save encrypted file
            encrypted_data = {
                'original_file': os.path.basename( file_path ),
                'cipher_type': cipher_type,
                'key': encryption_result.get( 'key' ),
                'encrypted_content': encryption_result['output'],
                'timestamp': datetime.now().isoformat()
            }
            
            with open( output_path, 'w', encoding='utf-8' ) as file:
                json.dump( encrypted_data, file, indent=2 )
            
            return {
                'success': True,
                'operation': 'file_encryption',
                'input_file': file_path,
                'output_file': output_path,
                'cipher': cipher_type,
                'key': encryption_result.get( 'key' ),
                'file_size': len( file_data )
            }
            
        except Exception as e:
            return {'error': f'File encryption failed: {str( e )}'}
    
    # File decryption
    def DecFile( self, enc_file: str, output_path: str = None, password: str = None ) -> Dict:
        print( f"\nDecrypting file: {enc_file}" )
        
        # Convert relative paths to absolute paths
        if not os.path.isabs( enc_file ):
            enc_file = os.path.join( self.script_dir, enc_file )
        
        if not os.path.exists( enc_file ):
            return {'error': f'Encrypted file not found: {enc_file}'}
        
        try:
            # Read encrypted file data
            with open( enc_file, 'r', encoding='utf-8' ) as file:
                encrypted_data = json.load( file )
            
            cipher_type = encrypted_data['cipher_type']
            key = password if password else encrypted_data.get( 'key' )
            encrypted_content = encrypted_data['encrypted_content']
            
            if not CRYPTO_AVAILABLE and cipher_type in ['fernet', 'aes']:
                return {'error': 'Cryptography library not installed. Run: pip install cryptography'}
            
            # Decrypt the content
            decryption_result = self.Decrypt( encrypted_content, cipher_type, key )
            
            if 'error' in decryption_result:
                return decryption_result
            
            # Decode from base64 back to binary
            file_data = base64.b64decode( decryption_result['output'] )
            
            # Determine output path
            if not output_path:
                original_name = encrypted_data.get( 'original_file', 'decrypted_file' )
                output_path = os.path.join( os.path.dirname(enc_file ), f"decrypted_{original_name}")
            
            # Save decrypted file
            with open( output_path, 'wb' ) as file:
                file.write( file_data )
            
            return {
                'success': True,
                'operation': 'file_decryption',
                'input_file': enc_file,
                'output_file': output_path,
                'cipher': cipher_type,
                'original_file': encrypted_data.get( 'original_file' ),
                'file_size': len( file_data )
            }
            
        except Exception as e:
            return {'error': f'File decryption failed: {str( e )}'}
    
    # Simple steganography - hide text in image
    def HideText( self, image_path: str, secret_text: str, output_path: str = None ) -> Dict:
        print( f"\nHiding text in image: {image_path}" )
        
        if not STEGANOGRAPHY_AVAILABLE:
            return {'error': 'PIL (Pillow) library not installed. Run: pip install Pillow numpy'}
        
        # Convert relative paths to absolute paths
        if not os.path.isabs( image_path ):
            image_path = os.path.join( self.script_dir, image_path )
        
        if not os.path.exists( image_path ):
            return {'error': f'Image file not found: {image_path}'}
        
        try:
            # Open image
            img = Image.open( image_path )
            img = img.convert( 'RGB' )
            img_array = np.array( img )
            
            # Convert text to binary
            binary_text = ''.join( format(ord(char ), '08b') for char in secret_text)
            binary_text += '1111111111111110'  # End marker
            
            # Check if image can hold the text
            max_capacity = img_array.size
            if len( binary_text ) > max_capacity:
                return {'error': f'Text too long for image. Max capacity: {max_capacity//8} characters'}
            
            # Hide text in LSB of image pixels
            flat_array = img_array.flatten()
            for i, bit in enumerate( binary_text ):
                if i < len( flat_array ):
                    flat_array[i] = (flat_array[i] & 0xFE) | int( bit )
            
            # Reshape and save
            stego_array = flat_array.reshape( img_array.shape )
            stego_img = Image.fromarray( stego_array.astype('uint8' ))
            
            if not output_path:
                output_path = image_path.replace( '.', '_stego.' )
            
            stego_img.save( output_path )
            
            return {
                'success': True,
                'operation': 'steganography_hide',
                'input_image': image_path,
                'output_image': output_path,
                'secret_text_length': len( secret_text ),
                'capacity_used': f"{len( binary_text )}/{max_capacity} bits"
            }
            
        except Exception as e:
            return {'error': f'Steganography failed: {str( e )}'}
    
    # Extract hidden text from image
    def ExtractText( self, image_path: str ) -> Dict:
        print( f"\nExtracting hidden text from image: {image_path}" )
        
        if not STEGANOGRAPHY_AVAILABLE:
            return {'error': 'PIL (Pillow) library not installed. Run: pip install Pillow numpy'}
        
        # Convert relative paths to absolute paths
        if not os.path.isabs( image_path ):
            image_path = os.path.join( self.script_dir, image_path )
        
        if not os.path.exists( image_path ):
            return {'error': f'Image file not found: {image_path}'}
        
        try:
            # Open image
            img = Image.open( image_path )
            img = img.convert( 'RGB' )
            img_array = np.array( img )
            
            # Extract LSB from pixels
            flat_array = img_array.flatten()
            binary_text = ''
            
            for pixel in flat_array:
                binary_text += str( pixel & 1 )
            
            # Find end marker and extract text
            end_marker = '1111111111111110'
            end_index = binary_text.find( end_marker )
            
            if end_index == -1:
                return {'error': 'No hidden text found or invalid end marker'}
            
            # Convert binary to text
            binary_text = binary_text[:end_index]
            secret_text = ''
            
            for i in range( 0, len(binary_text ), 8):
                byte = binary_text[i:i+8]
                if len( byte ) == 8:
                    secret_text += chr( int(byte, 2 ))
            
            return {
                'success': True,
                'operation': 'steganography_extract',
                'input_image': image_path,
                'extracted_text': secret_text,
                'text_length': len( secret_text )
            }
            
        except Exception as e:
            return {'error': f'Text extraction failed: {str( e )}'}
    
    # Generate secure password
    def GenPassword( self, length: int = 16, include_symbols: bool = True ) -> str:
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        return ''.join( secrets.choice(characters ) for _ in range( length ))
    
    # Generate cryptographic key
    def GenKey( self, cipher_type: str ) -> Dict:
        """Generate appropriate key for specified cipher type"""
        if cipher_type.lower() == 'caesar':
            key = secrets.randbelow( 25 ) + 1
            return {'cipher': 'Caesar', 'key': key}
        
        elif cipher_type.lower() == 'vigenere':
            length = secrets.randbelow( 10 ) + 5  # 5-15 characters
            key = ''.join( secrets.choice(string.ascii_uppercase ) for _ in range( length ))
            return {'cipher': 'Vigenere', 'key': key}
        
        elif cipher_type.lower() == 'xor':
            key = self.GenPassword( 16, False )
            return {'cipher': 'XOR', 'key': key}
        
        elif cipher_type.lower() == 'fernet':
            if CRYPTO_AVAILABLE:
                key = base64.urlsafe_b64encode( Fernet.generate_key( )).decode()
                return {'cipher': 'Fernet', 'key': key}
            else:
                return {'error': 'Cryptography library not installed'}
        
        elif cipher_type.lower() == 'aes':
            key = self.GenPassword( 32, False )
            return {'cipher': 'AES', 'key': key}
        
        else:
            return {'error': f'Key generation not supported for {cipher_type}'}
    
    # Analyze encrypted text
    def Analyze( self, ciphertext: str ) -> Dict:
        print( "\nAnalyzing encrypted text..." )
        
        analysis = {
            'length': len( ciphertext ),
            'character_types': {},
            'patterns': {},
            'possible_ciphers': []
        }
        
        # Character analysis
        analysis['character_types'] = {
            'letters': sum( 1 for c in ciphertext if c.isalpha( )),
            'digits': sum( 1 for c in ciphertext if c.isdigit( )),
            'spaces': ciphertext.count( ' ' ),
            'special_chars': sum( 1 for c in ciphertext if not c.isalnum( ) and c != ' ')
        }
        
        # Pattern analysis
        if all( c in '01 ' for c in ciphertext ):
            analysis['possible_ciphers'].append( 'Binary' )
        
        if all( c in '0123456789abcdefABCDEF' for c in ciphertext ):
            analysis['possible_ciphers'].append( 'Hexadecimal' )
        
        if all( c in '.-/ ' for c in ciphertext ):
            analysis['possible_ciphers'].append( 'Morse Code' )
        
        if re.match( r'^[A-Za-z0-9+/]*={0,2}$', ciphertext ):
            analysis['possible_ciphers'].append( 'Base64' )
        
        if analysis['character_types']['letters'] > 0 and analysis['character_types']['special_chars'] == 0:
            analysis['possible_ciphers'].extend( ['Caesar', 'Vigenere', 'Atbash', 'ROT13', 'Substitution'] )
        
        if '=' in ciphertext and len( ciphertext ) > 50:
            analysis['possible_ciphers'].extend( ['Fernet', 'AES'] )
        
        return {
            'success': True,
            'operation': 'text_analysis',
            'input': ciphertext[:100] + '...' if len( ciphertext ) > 100 else ciphertext,
            'analysis': analysis
        }
    
    # Display results in formatted way
    def ShowResults( self, results: Dict ):
        if 'error' in results:
            print( f"\nError: {results['error']}" )
            return
        
        print( f"\n{'='*60}" )
        print( f"CRYPTO ANALYZER RESULTS" )
        print( f"{'='*60}" )
        
        operation = results.get( 'operation', 'unknown' )
        
        if operation in ['encryption', 'decryption']:
            self._ShowCipher( results )
        elif operation == 'brute_force':
            self._ShowBrute( results )
        elif operation in ['file_encryption', 'file_decryption']:
            self._ShowFile( results )
        elif operation in ['steganography_hide', 'steganography_extract']:
            self._ShowStego( results )
        elif operation == 'text_analysis':
            self._ShowAnalysis( results )
        
        print( f"{'='*60}" )
    
    # Display cipher operation results
    def _ShowCipher( self, results: Dict ):
        print( f"Operation: {results['operation'].title( )}")
        print( f"Cipher: {results['cipher']}" )
        print( f"Key: {results.get('key', 'N/A' )}")
        print( f"\nInput: {results['input'][:100]}{'...' if len(results['input'] ) > 100 else ''}")
        print( f"Output: {results['output'][:100]}{'...' if len(results['output'] ) > 100 else ''}")
    
    # Display brute force results
    def _ShowBrute( self, results: Dict ):
        print( f"Operation: Caesar Cipher Brute Force" )
        print( f"Input: {results['input']}" )
        print( f"\nTop 5 Most Likely Results:" )
        
        for i, result in enumerate( results['results'], 1 ):
            print( f"{i}. Shift {result['shift']:2d}: {result['decrypted'][:80]}{'...' if len(result['decrypted'] ) > 80 else ''}")
            print( f"   Readability Score: {result['readable_score']:.2f}" )
    
    # Display file operation results
    def _ShowFile( self, results: Dict ):
        print( f"Operation: {results['operation'].replace('_', ' ' ).title()}")
        print( f"Cipher: {results.get('cipher', 'N/A' )}")
        print( f"Input File: {results.get('input_file', 'N/A' )}")
        print( f"Output File: {results.get('output_file', 'N/A' )}")
        print( f"File Size: {results.get('file_size', 0 )} bytes")
        if 'key' in results:
            print( f"Key: {results['key']}" )
    
    # Display steganography results
    def _ShowStego( self, results: Dict ):
        if results['operation'] == 'steganography_hide':
            print( f"Operation: Hide Text in Image" )
            print( f"Input Image: {results['input_image']}" )
            print( f"Output Image: {results['output_image']}" )
            print( f"Secret Text Length: {results['secret_text_length']} characters" )
            print( f"Capacity Used: {results['capacity_used']}" )
        else:
            print( f"Operation: Extract Text from Image" )
            print( f"Input Image: {results['input_image']}" )
            print( f"Extracted Text: {results['extracted_text'][:100]}{'...' if len(results['extracted_text'] ) > 100 else ''}")
            print( f"Text Length: {results['text_length']} characters" )
    
    # Display analysis results
    def _ShowAnalysis( self, results: Dict ):
        analysis = results['analysis']
        print( f"Operation: Ciphertext Analysis" )
        print( f"Input: {results['input']}" )
        print( f"\nCharacter Analysis:" )
        print( f"  Length: {analysis['length']}" )
        print( f"  Letters: {analysis['character_types']['letters']}" )
        print( f"  Digits: {analysis['character_types']['digits']}" )
        print( f"  Spaces: {analysis['character_types']['spaces']}" )
        print( f"  Special Characters: {analysis['character_types']['special_chars']}" )
        print( f"\nPossible Cipher Types:" )
        for cipher in analysis['possible_ciphers']:
            print( f"  - {cipher}" )
    
    # Display help information
    def ShowHelp( self ):
        print( f"\n{'='*60}" )
        print( f"CRYPTO ANALYZER - HELP" )
        print( f"{'='*60}" )
        print( f"Commands:" )
        print( f"  encrypt <cipher> <text> [key]    - Encrypt text" )
        print( f"  decrypt <cipher> <text> [key]    - Decrypt text" )
        print( f"  brute <text>                     - Brute force Caesar cipher" )
        print( f"  analyze <text>                   - Analyze ciphertext" )
        print( f"  file-encrypt <file> [cipher]     - Encrypt file" )
        print( f"  file-decrypt <file> [password]   - Decrypt file" )
        print( f"  hide-text <image> <text>         - Hide text in image" )
        print( f"  extract-text <image>             - Extract text from image" )
        print( f"  generate-key <cipher>            - Generate key for cipher" )
        print( f"  generate-password [length]       - Generate secure password" )
        print( f"  help                             - Show this help message" )
        print( f"  quit, exit                       - Exit the program" )
        print( f"\nSupported Ciphers:" )
        for cipher in self.ciphers:
            print( f"  - {cipher}" )
        print( f"\nExample usage:" )
        print( f"  encrypt caesar 'Hello World' 3" )
        print( f"  decrypt base64 'SGVsbG8gV29ybGQ='" )
        print( f"  brute 'Khoor Zruog'" )
        print( f"  file-encrypt sample.txt fernet" )
        print( f"  generate-password 20" )
        print( f"{'='*60}" )
    
    # Parse command line with proper quote handling
    def _ParseCmd( self, command_line: str ) -> List[str]:
        import shlex
        try:
            # Use shlex to properly handle quoted strings
            return shlex.split( command_line )
        except ValueError:
            # Fallback to simple split if shlex fails
            return command_line.split()
    

# Main function to run the crypto analyzer
def Main():
    analyzer = CryptoTool()
    
    # Check if input is being piped or if running interactively
    is_interactive = sys.stdin.isatty()
    
    if is_interactive:
        print( "Crypto Analyzer - Encryption/Decryption Tool" )
        print( "Type 'help' for commands or 'quit' to exit" )
        
        # Check for optional dependencies
        if not CRYPTO_AVAILABLE:
            print( "\nNote: Install 'cryptography' for advanced encryption (Fernet, AES )")
            print( "Run: pip install cryptography" )
        
        if not STEGANOGRAPHY_AVAILABLE:
            print( "\nNote: Install 'Pillow' and 'numpy' for steganography features" )
            print( "Run: pip install Pillow numpy" )
    
    while True:
        try:
            if is_interactive:
                user_input = input( "\ncrypto-analyzer> " ).strip()
            else:
                # Handle piped input
                line = sys.stdin.readline()
                if not line:  # EOF reached
                    break
                user_input = line.strip()
            
            if not user_input:
                continue
            
            command_parts = user_input.split()
            command = command_parts[0].lower()
            
            if command in ['quit', 'exit', 'q']:
                print( "Thank you for using Crypto Analyzer!" )
                break
            
            elif command == 'help':
                analyzer.ShowHelp()
            
            elif command == 'encrypt':
                # Parse command with proper quote handling
                parts = analyzer._ParseCmd( user_input )
                if len( parts ) < 3:
                    print( "Usage: encrypt <cipher> <text> [key]" )
                    continue
                
                cipher_type = parts[1]
                text = parts[2]
                key = parts[3] if len( parts ) > 3 else None
                
                results = analyzer.Encrypt( text, cipher_type, key )
                analyzer.ShowResults( results )
            
            elif command == 'decrypt':
                # Parse command with proper quote handling
                parts = analyzer._ParseCmd( user_input )
                if len( parts ) < 3:
                    print( "Usage: decrypt <cipher> <text> [key]" )
                    continue
                
                cipher_type = parts[1]
                text = parts[2]
                key = parts[3] if len( parts ) > 3 else None
                
                results = analyzer.Decrypt( text, cipher_type, key )
                analyzer.ShowResults( results )
            
            elif command == 'brute':
                if len( command_parts ) < 2:
                    print( "Usage: brute <ciphertext>" )
                    continue
                
                ciphertext = ' '.join( command_parts[1:] )
                results = analyzer.BruteForce( ciphertext )
                analyzer.ShowResults( results )
            
            elif command == 'analyze':
                if len( command_parts ) < 2:
                    print( "Usage: analyze <ciphertext>" )
                    continue
                
                ciphertext = ' '.join( command_parts[1:] )
                results = analyzer.Analyze( ciphertext )
                analyzer.ShowResults( results )
            
            elif command == 'file-encrypt':
                if len( command_parts ) < 2:
                    print( "Usage: file-encrypt <file_path> [cipher_type]" )
                    continue
                
                file_path = command_parts[1]
                cipher_type = command_parts[2] if len( command_parts ) > 2 else 'fernet'
                results = analyzer.EncFile( file_path, cipher_type=cipher_type )
                analyzer.ShowResults( results )
            
            elif command == 'file-decrypt':
                if len( command_parts ) < 2:
                    print( "Usage: file-decrypt <encrypted_file> [password]" )
                    continue
                
                file_path = command_parts[1]
                password = command_parts[2] if len( command_parts ) > 2 else None
                results = analyzer.DecFile( file_path, password=password )
                analyzer.ShowResults( results )
            
            elif command == 'hide-text':
                if len( command_parts ) < 3:
                    print( "Usage: hide-text <image_path> <secret_text>" )
                    continue
                
                image_path = command_parts[1]
                secret_text = ' '.join( command_parts[2:] )
                results = analyzer.HideText( image_path, secret_text )
                analyzer.ShowResults( results )
            
            elif command == 'extract-text':
                if len( command_parts ) < 2:
                    print( "Usage: extract-text <image_path>" )
                    continue
                
                image_path = command_parts[1]
                results = analyzer.ExtractText( image_path )
                analyzer.ShowResults( results )
            
            elif command == 'generate-key':
                if len( command_parts ) < 2:
                    print( "Usage: generate-key <cipher_type>" )
                    continue
                
                cipher_type = command_parts[1]
                results = analyzer.GenKey( cipher_type )
                if 'error' in results:
                    print( f"Error: {results['error']}" )
                else:
                    print( f"Generated {results['cipher']} key: {results['key']}" )
            
            elif command == 'generate-password':
                length = int( command_parts[1] ) if len( command_parts ) > 1 else 16
                password = analyzer.GenPassword( length )
                print( f"Generated secure password: {password}" )
            
            else:
                print( f"Unknown command: {command}" )
                print( "Type 'help' for available commands" )
        
        except KeyboardInterrupt:
            print( "\n\nExiting Crypto Analyzer..." )
            break
        except EOFError:
            # Handle EOF (Ctrl+D or piped input ending)
            if is_interactive:
                print( "\n\nExiting Crypto Analyzer..." )
            break
        except Exception as e:
            print( f"\nError: {str( e )}")

if __name__ == "__main__":
    Main()
