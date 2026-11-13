"""
Author: Andrew Piggot

Purpose: Provide authenticated encryption, educational ciphers, ciphertext analysis,
password generation, and PNG steganography for data you own or may inspect.

Usage: Run from the project root:
    python crypto_tools/crypto_analyzer.py
    python crypto_tools/crypto_analyzer.py encrypt caesar "Hello World" 3
    python crypto_tools/crypto_analyzer.py file-encrypt crypto_tools/sample_document.txt aes
    python crypto_tools/crypto_analyzer.py analyze "SGVsbG8=" --json
    python crypto_tools/crypto_analyzer.py --help

    No arguments opens the interactive prompt. Cryptography and Pillow are optional
    dependencies for authenticated encryption and image operations respectively.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import io
import json
import math
import os
import re
import secrets
import shlex
import string
import sys
from collections import Counter
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from PIL import Image

    STEGANOGRAPHY_AVAILABLE = True
except ImportError:
    STEGANOGRAPHY_AVAILABLE = False


AES_MAGIC = b'ACT2'
STEGO_MAGIC = b'ACTS2'
KDF_ROUNDS = 600_000
MAX_BYTES = 32 * 1024 * 1024
MAX_IMAGE_PIXELS = 16_000_000
ALPHABET = string.ascii_uppercase
MORSE_CODES = ( 
    '.- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. '
    '--.- .-. ... - ..- ...- .-- -..- -.-- --.. '
    '----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----.'
).split( )


# Reject malformed transport data instead of silently discarding invalid characters.
def Decode64( text, url=False ):
    return base64.b64decode( 
        text.encode( 'ascii' ),
        altchars=b'-_' if url else None,
        validate=True,
    )


# Exclusive creation prevents overwrites and following destination symlinks.
def WriteNew( path, data ):
    path = Path( path ).expanduser( )

    if '..' in path.parts:
        raise ValueError( 'Use an explicit output path without parent traversal (..)' )

    descriptor = os.open( path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 )

    with os.fdopen( descriptor, 'wb' ) as handle:
        handle.write( data )

    return str( path.absolute( ) )


# Bound reads before allocating encryption or image buffers.
def ReadBytes( path, limit=MAX_BYTES ):
    with Path( path ).expanduser( ).open( 'rb' ) as handle:
        data = handle.read( limit + 1 )

    if len( data ) > limit:
        raise ValueError( f'Input exceeds the {limit} byte limit' )

    return data


# Public methods return result dictionaries without printing or retaining secret history.
class CryptoTool:
    def __init__( self ):
        self.ciphers = [
            'caesar',
            'vigenere',
            'atbash',
            'rot13',
            'base64',
            'hex',
            'aes',
            'fernet',
            'xor',
            'substitution',
            'morse',
            'binary',
        ]
        self.results = {}
        self.file_ops = {}
        self.stego_results = {}
        self.script_dir = Path( __file__ ).resolve( ).parent
        self.morse = dict( zip( ALPHABET + string.digits, MORSE_CODES ) )
        self.morse[' '] = '/'
        self.rev_morse = { value: key for key, value in self.morse.items( ) }

    def Encrypt( self, plaintext, cipher_type, key=None, **kwargs ):
        return self.Transform( plaintext, cipher_type, key, True, **kwargs )

    def Decrypt( self, ciphertext, cipher_type, key=None, **kwargs ):
        return self.Transform( ciphertext, cipher_type, key, False, **kwargs )

    def Transform( self, text, cipher_type, key, encrypt, **kwargs ):
        try:
            if not isinstance( text, str ) or not isinstance( cipher_type, str ):
                raise ValueError( 'Text and cipher must be strings' )

            if len( text.encode( 'utf-8' ) ) > MAX_BYTES:
                raise ValueError( 'Text exceeds the 32 MiB input limit' )

            cipher = cipher_type.lower( )

            if cipher not in self.ciphers:
                raise ValueError( f'Unsupported cipher: {cipher}' )

            if cipher in ( 'aes', 'fernet' ):
                output, used_key = self.CryptText( 
                    text,
                    cipher,
                    key,
                    encrypt,
                    legacy=kwargs.get( 'legacy', False ),
                )
            else:
                output, used_key = self.Classic( 
                    text,
                    cipher,
                    key,
                    encrypt,
                    kwargs.get( 'substitution_key' ),
                )

            result = {
                'success': True,
                'cipher': cipher,
                'input': text,
                'output': output,
                'operation': 'encryption' if encrypt else 'decryption',
            }

            if used_key is not None:
                result['key'] = used_key

            if cipher not in ( 'aes', 'fernet' ):
                result['warning'] = 'Educational cipher or encoding; not secure data protection.'
            elif kwargs.get( 'legacy' ):
                result['warning'] = 'Legacy recovery: AES-CBC data has no authenticity guarantee.'

            return result
        except ( ValueError, TypeError, UnicodeError, binascii.Error ) as exc:
            return { 'error': str( exc ) }

    # Shift ASCII letters only; preserve Unicode, punctuation, and case.
    def Shift( self, text, shifts ):
        result = []
        index = 0

        for char in text:
            if char in string.ascii_letters:
                base = ord( 'A' ) if char in ALPHABET else ord( 'a' )
                shift = shifts[index % len( shifts )]
                result.append( chr( ( ord( char ) - base + shift ) % 26 + base ) )
                index += 1
            else:
                result.append( char )

        return ''.join( result )

    # Encodings and XOR operate on UTF-8 bytes; classical alphabets remain ASCII.
    def Classic( self, text, cipher, key, encrypt, key_map ):
        direction = 1 if encrypt else -1

        if cipher in ( 'caesar', 'rot13' ):
            shift = 13 if cipher == 'rot13' else int( key if key is not None else 3 )

            return self.Shift( text, [ shift * direction ] ), shift

        if cipher == 'vigenere':
            if not isinstance( key, str ) or not re.fullmatch( r'[A-Za-z]+', key ):
                raise ValueError( 'Vigenere requires a nonempty ASCII-letter key' )

            shifts = [ ( ord( char ) - 65 ) * direction for char in key.upper( ) ]

            return self.Shift( text, shifts ), key

        if cipher == 'atbash':
            mapping = str.maketrans( 
                ALPHABET + ALPHABET.lower( ),
                ALPHABET[::-1] + ALPHABET[::-1].lower( ),
            )

            return text.translate( mapping ), None

        if cipher == 'substitution':
            if key_map is None and key:
                if len( str( key ) ) != 26:
                    raise ValueError( 'Substitution alphabet must contain exactly 26 letters' )

                key_map = dict( zip( ALPHABET, str( key ).upper( ) ) )

            if key_map is None:
                if not encrypt:
                    raise ValueError( 'Substitution decryption requires the original alphabet/map' )

                shuffled = secrets.SystemRandom( ).sample( ALPHABET, len( ALPHABET ) )
                key_map = dict( zip( ALPHABET, shuffled ) )

            if not isinstance( key_map, dict ) or set( key_map ) != set( ALPHABET ):
                raise ValueError( 'Substitution keys must map all 26 uppercase letters' )

            if any( not isinstance( value, str ) for value in key_map.values( ) ):
                raise ValueError( 'Substitution values must be uppercase letters' )

            if set( key_map.values( ) ) != set( ALPHABET ):
                raise ValueError( 'Substitution values must be a unique uppercase alphabet' )

            mapping = key_map if encrypt else { value: name for name, value in key_map.items( ) }
            mapping = mapping | { name.lower( ): value.lower( ) for name, value in mapping.items( ) }

            return text.translate( str.maketrans( mapping ) ), key_map

        if cipher == 'xor':
            if not isinstance( key, str ) or not key:
                raise ValueError( 'XOR requires a nonempty text key' )

            data = text.encode( 'utf-8' ) if encrypt else Decode64( text )
            key_bytes = key.encode( 'utf-8' )
            output = bytes( 
                value ^ key_bytes[index % len( key_bytes )]
                for index, value in enumerate( data )
            )
            encoded = base64.b64encode( output ).decode( 'ascii' ) if encrypt else output.decode( 'utf-8' )

            return encoded, key

        if cipher == 'morse':
            parts = list( text.upper( ) ) if encrypt else text.split( )
            mapping = self.morse if encrypt else self.rev_morse

            if any( part not in mapping for part in parts ):
                raise ValueError( 'Morse supports A-Z, digits, and spaces; unknown symbols found' )

            return ( ' ' if encrypt else '' ).join( mapping[part] for part in parts ), None

        if encrypt:
            data = text.encode( 'utf-8' )

            if cipher == 'base64':
                return base64.b64encode( data ).decode( 'ascii' ), None

            if cipher == 'hex':
                return data.hex( ), None

            return ' '.join( format( byte, '08b' ) for byte in data ), None

        if cipher == 'base64':
            data = Decode64( text )
        elif cipher == 'hex':
            data = bytes.fromhex( text )
        else:
            parts = text.split( )

            if any( not re.fullmatch( r'[01]{8}', part ) for part in parts ):
                raise ValueError( 'Binary input must contain space-separated 8-bit bytes' )

            data = bytes( int( part, 2 ) for part in parts )

        return data.decode( 'utf-8' ), None

    # Authenticate version/settings as well as ciphertext; use fresh salt and nonce each time.
    def AesBytes( self, data, password, encrypt, legacy=False ):
        if not password or not isinstance( password, str ):
            raise ValueError( 'AES requires a password' )

        if encrypt:
            salt = secrets.token_bytes( 16 )
            nonce = secrets.token_bytes( 12 )
            header = AES_MAGIC + KDF_ROUNDS.to_bytes( 4, 'big' ) + salt + nonce
            rounds = KDF_ROUNDS
        else:
            if not data.startswith( AES_MAGIC ):
                if legacy:
                    return self.LegacyAes( data, password )

                raise ValueError( 'Unsupported AES format; use --legacy only for trusted old CBC data' )

            if len( data ) < 52:
                raise ValueError( 'Truncated AES payload' )

            rounds = int.from_bytes( data[4:8], 'big' )

            if rounds != KDF_ROUNDS:
                raise ValueError( 'Unsupported AES key-derivation settings' )

            header, salt, nonce = data[:36], data[8:24], data[24:36]

        kdf = PBKDF2HMAC( 
            algorithm=hashes.SHA256( ),
            length=32,
            salt=salt,
            iterations=rounds,
        )
        aes = AESGCM( kdf.derive( password.encode( 'utf-8' ) ) )

        if encrypt:
            return header + aes.encrypt( nonce, data, header )

        return aes.decrypt( nonce, data[36:], header )

    # Legacy CBC lacks authentication; callers must explicitly opt in to recovery.
    def LegacyAes( self, data, password ):
        if len( data ) < 48 or ( len( data ) - 32 ) % 16:
            raise ValueError( 'Invalid legacy AES payload length' )

        kdf = PBKDF2HMAC( 
            algorithm=hashes.SHA256( ),
            length=32,
            salt=data[:16],
            iterations=100_000,
        )
        cipher = Cipher( 
            algorithms.AES( kdf.derive( password.encode( 'utf-8' ) ) ),
            modes.CBC( data[16:32] ),
        )
        decryptor = cipher.decryptor( )
        padded = decryptor.update( data[32:] ) + decryptor.finalize( )
        unpadder = padding.PKCS7( 128 ).unpadder( )

        return unpadder.update( padded ) + unpadder.finalize( )

    def CryptText( self, text, cipher, key, encrypt, legacy=False ):
        if not CRYPTO_AVAILABLE:
            raise ValueError( 'Install encryption support: python -m pip install cryptography' )

        if encrypt and key is None:
            key = Fernet.generate_key( ).decode( 'ascii' ) if cipher == 'fernet' else self.GenPassword( 32 )

        if not isinstance( key, str ) or not key:
            raise ValueError( 'Supply the original text key/password' )

        try:
            if cipher == 'aes':
                data = text.encode( 'utf-8' ) if encrypt else Decode64( text )
                output = self.AesBytes( data, key, encrypt, legacy )
                encoded = base64.b64encode( output ).decode( 'ascii' ) if encrypt else output.decode( 'utf-8' )

                return encoded, key

            key_data = key.encode( 'ascii' )

            if len( Decode64( key, url=True ) ) != 32:
                key_data = Decode64( key, url=True )

            fernet = Fernet( key_data )

            if encrypt:
                output = fernet.encrypt( text.encode( 'utf-8' ) ).decode( 'ascii' )

                return output, key_data.decode( 'ascii' )

            token = text.encode( 'ascii' )

            if not token.startswith( b'gAAAA' ):
                token = Decode64( text, url=True )

            return fernet.decrypt( token ).decode( 'utf-8' ), key_data.decode( 'ascii' )
        except ( InvalidTag, InvalidToken ):
            raise ValueError( 'Authentication failed: wrong key/password or modified ciphertext' ) from None

    # Keys never enter encrypted envelopes; generated secrets are returned separately.
    def EncFile( self, file_path, output_path=None, cipher_type='fernet', password=None ):
        try:
            cipher = cipher_type.lower( )

            if cipher not in ( 'aes', 'fernet' ):
                raise ValueError( 'File encryption requires aes or fernet' )

            source = Path( file_path ).expanduser( )
            data = ReadBytes( source, MAX_BYTES // 2 )
            result = self.Encrypt( base64.b64encode( data ).decode( 'ascii' ), cipher, password )

            if 'error' in result:
                return result

            envelope = {
                'version': 2,
                'cipher_type': cipher,
                'encrypted_content': result['output'],
            }
            dest = WriteNew( 
                output_path or str( source ) + '.encrypted',
                json.dumps( envelope, indent=2 ).encode( 'utf-8' ),
            )

            return {
                'success': True,
                'operation': 'file_encryption',
                'input_file': str( source ),
                'output_file': dest,
                'cipher': cipher,
                'key': result['key'],
                'file_size': len( data ),
                'warning': 'Keep the returned key/password separately; it is not in the encrypted file.',
            }
        except ( OSError, ValueError, TypeError ) as exc:
            return { 'error': str( exc ) }

    # Ignore legacy embedded names/keys so untrusted metadata cannot choose output paths.
    def DecFile( self, enc_file, output_path=None, password=None, *, legacy=False ):
        try:
            source = Path( enc_file ).expanduser( )
            envelope = json.loads( ReadBytes( source ).decode( 'utf-8' ) )

            if not isinstance( envelope, dict ):
                raise ValueError( 'Encrypted file must contain a JSON object' )

            version = envelope.get( 'version' )

            if version != 2 and not ( version is None and legacy ):
                raise ValueError( 'Unsupported file format; old files require --legacy and an external key' )

            cipher = envelope.get( 'cipher_type' )
            content = envelope.get( 'encrypted_content' )

            if cipher not in ( 'aes', 'fernet' ) or not isinstance( content, str ):
                raise ValueError( 'Invalid encrypted file fields' )

            if not password:
                raise ValueError( 'Supply the key/password separately; embedded keys are not used' )

            result = self.Decrypt( content, cipher, password, legacy=legacy )

            if 'error' in result:
                return result

            data = Decode64( result['output'] )
            dest = WriteNew( output_path or str( source ) + '.decrypted', data )

            return {
                'success': True,
                'operation': 'file_decryption',
                'input_file': str( source ),
                'output_file': dest,
                'cipher': cipher,
                'file_size': len( data ),
            }
        except ( OSError, ValueError, TypeError, UnicodeError ) as exc:
            return { 'error': str( exc ) }

    # Length-prefixed UTF-8 avoids the old delimiter collisions; checksum detects damage.
    def HideText( self, image_path, secret_text, output_path=None ):
        try:
            image = self.LoadImage( image_path )
            data = secret_text.encode( 'utf-8' )
            payload = ( 
                STEGO_MAGIC
                + len( data ).to_bytes( 4, 'big' )
                + hashlib.sha256( data ).digest( )
                + data
            )
            pixels = bytearray( image.tobytes( ) )

            if len( payload ) * 8 > len( pixels ):
                raise ValueError( f'Image capacity is {max( 
                    0,
                    len( pixels ) // 8 - 41,
                )} UTF-8 bytes' )

            for index, byte in enumerate( payload ):
                for bit in range( 8 ):
                    offset = index * 8 + bit
                    pixels[offset] = ( pixels[offset] & 254 ) | ( ( byte >> ( 7 - bit ) ) & 1 )

            source = Path( image_path )
            dest = Path( output_path ) if output_path else source.with_name( source.stem + '_stego.png' )

            if dest.suffix.lower( ) != '.png':
                raise ValueError( 'Steganography output must be a lossless .png file' )

            result = Image.frombytes( 'RGB', image.size, bytes( pixels ) )
            buffer = io.BytesIO( )
            result.save( buffer, format='PNG' )
            saved = WriteNew( dest, buffer.getvalue( ) )

            return {
                'success': True,
                'operation': 'steganography_hide',
                'input_image': str( image_path ),
                'output_image': saved,
                'secret_text_length': len( secret_text ),
                'capacity_used': f'{len( payload ) * 8}/{len( pixels )} bits',
                'warning': 'Steganography hides data; it does not encrypt or authenticate it.',
            }
        except ( OSError, ValueError, TypeError ) as exc:
            return { 'error': str( exc ) }

    def LoadImage( self, path ):
        if not STEGANOGRAPHY_AVAILABLE:
            raise ValueError( 'Install image support: python -m pip install Pillow' )

        try:
            with Image.open( io.BytesIO( ReadBytes( path ) ) ) as image:
                if image.width * image.height > MAX_IMAGE_PIXELS:
                    raise ValueError( 'Image exceeds the 16 megapixel limit' )

                return image.convert( 'RGB' )
        except Image.DecompressionBombError:
            raise ValueError( 'Image exceeds safe decompression limits' ) from None

    def ExtractText( self, image_path ):
        try:
            pixels = self.LoadImage( image_path ).tobytes( )

            if len( pixels ) < 41 * 8:
                raise ValueError( 'No supported hidden payload' )

            header = self.ReadBits( pixels, 41 )

            if header[:5] != STEGO_MAGIC:
                raise ValueError( 'No version-2 hidden payload; legacy sentinel images are unsupported' )

            size = int.from_bytes( header[5:9], 'big' )

            if size > len( pixels ) // 8 - 41:
                raise ValueError( 'Invalid hidden payload length' )

            data = self.ReadBits( pixels[41 * 8:], size )

            if hashlib.sha256( data ).digest( ) != header[9:41]:
                raise ValueError( 'Hidden payload checksum failed' )

            text = data.decode( 'utf-8' )

            return {
                'success': True,
                'operation': 'steganography_extract',
                'input_image': str( image_path ),
                'extracted_text': text,
                'text_length': len( text ),
            }
        except ( OSError, ValueError, TypeError ) as exc:
            return { 'error': str( exc ) }

    def ReadBits( self, pixels, count ):
        output = bytearray( )

        for index in range( count ):
            byte = 0

            for bit in range( 8 ):
                byte = ( byte << 1 ) | ( pixels[index * 8 + bit] & 1 )

            output.append( byte )

        return bytes( output )

    def GenPassword( self, length=16, include_symbols=True ):
        if type( length ) is not int or not 8 <= length <= 1024:
            raise ValueError( 'Password length must be an integer between 8 and 1024' )

        alphabet = string.ascii_letters + string.digits

        if include_symbols:
            alphabet += '!@#$%^&*()_+-=[]{}|;:,.<>?'

        return ''.join( secrets.choice( alphabet ) for _ in range( length ) )

    def GenKey( self, cipher_type ):
        cipher = cipher_type.lower( )

        if cipher == 'fernet':
            if not CRYPTO_AVAILABLE:
                return { 'error': 'Install cryptography for Fernet key generation' }

            key = Fernet.generate_key( ).decode( 'ascii' )
        elif cipher == 'caesar':
            key = secrets.randbelow( 25 ) + 1
        elif cipher == 'vigenere':
            key = ''.join( secrets.choice( ALPHABET ) for _ in range( 16 ) )
        elif cipher == 'substitution':
            key = ''.join( secrets.SystemRandom( ).sample( ALPHABET, 26 ) )
        elif cipher in ( 'aes', 'xor' ):
            key = self.GenPassword( 32, False )
        else:
            return { 'error': f'Key generation not supported for {cipher}' }

        return { 'cipher': cipher, 'key': key, 'success': True }

    # English ranking is a heuristic, not proof of the original plaintext.
    def _CalcScore( self, text ):
        letters = [ char for char in text.upper( ) if char in ALPHABET ]

        if not letters:
            return 0.0

        common = sum( char in 'ETAOINSHRDLU' for char in letters ) / len( letters )
        words = re.findall( r'[A-Z]+', text.upper( ) )
        hits = sum( word in { 'THE', 'AND', 'HELLO', 'WORLD', 'THIS', 'IS', 'A' } for word in words )

        return round( min( 10.0, common * 5 + hits ), 2 )

    def BruteForce( self, ciphertext ):
        rows = []

        for shift in range( 26 ):
            output = self.Shift( ciphertext, [ -shift ] )
            rows.append( 
                {
                    'shift': shift,
                    'decrypted': output,
                    'readable_score': self._CalcScore( output ),
                }
            )

        rows.sort( key=lambda row: row['readable_score'], reverse=True )

        return {
            'success': True,
            'operation': 'brute_force',
            'input': ciphertext,
            'results': rows,
            'warning': 'English scores are heuristic; all 26 shifts are included.',
        }

    def Analyze( self, ciphertext ):
        data = ciphertext.encode( 'utf-8' )
        counts = Counter( data )
        entropy = -sum( 
            ( count / len( data ) ) * math.log2( count / len( data ) )
            for count in counts.values( )
        )
        possible = []

        if ciphertext:
            if re.fullmatch( r'[01]{8}(?:\s+[01]{8})*', ciphertext ):
                possible.append( 'Binary' )

            if re.fullmatch( r'(?:[0-9a-fA-F]{2})+', ciphertext ):
                possible.append( 'Hexadecimal' )

            if ciphertext.strip( ) and all( part in self.rev_morse for part in ciphertext.split( ) ):
                possible.append( 'Morse Code' )

            try:
                decoded = Decode64( ciphertext, url=True )
                possible.append( 'Base64-compatible encoding' )

                if decoded.startswith( AES_MAGIC ):
                    possible.append( 'Crypto Analyzer AES-GCM envelope' )
            except ( ValueError, UnicodeError ):
                pass

        return {
            'success': True,
            'operation': 'text_analysis',
            'input': ciphertext,
            'analysis': {
                'length': len( ciphertext ),
                'byte_length': len( data ),
                'entropy_bits_per_byte': round( entropy, 4 ),
                'character_types': {
                    'letters': sum( char.isalpha( ) for char in ciphertext ),
                    'digits': sum( char.isdigit( ) for char in ciphertext ),
                    'spaces': sum( char.isspace( ) for char in ciphertext ),
                },
                'possible_ciphers': possible,
            },
            'warning': 'Patterns and sample entropy cannot establish encryption type or strength.',
        }

    def ShowResults( self, results ):
        print( json.dumps( results, indent=2, ensure_ascii=True ) )

    def ShowHelp( self ):
        BuildParser( ).print_help( )

    # Disable escape processing so Windows backslashes survive interactive parsing.
    def _ParseCmd( self, command_line ):
        lexer = shlex.shlex( command_line, posix=True )
        lexer.whitespace_split = True
        lexer.commenters = ''
        lexer.escape = ''

        return list( lexer )


# CLI and prompt share one parser and command implementation.
def BuildParser( ):
    parser = argparse.ArgumentParser( 
        description='Authenticated encryption and educational crypto tools for authorized data.',
        epilog='Example: python crypto_tools/crypto_analyzer.py encrypt caesar "Hello World" 3',
    )
    commands = parser.add_subparsers( dest='command', required=True )

    for name in ( 'encrypt', 'decrypt' ):
        cmd = commands.add_parser( name )
        cmd.add_argument( 'cipher', choices=CryptoTool( ).ciphers )
        cmd.add_argument( 'text' )
        cmd.add_argument( 'key', nargs='?' )
        cmd.add_argument( '--legacy', action='store_true' )
        cmd.add_argument( '--key-file', type=Path )

    for name in ( 'analyze', 'brute' ):
        cmd = commands.add_parser( name )
        cmd.add_argument( 'text' )

    cmd = commands.add_parser( 'file-encrypt' )
    cmd.add_argument( 'path' )
    cmd.add_argument( 'cipher', nargs='?', default='fernet', choices=( 'fernet', 'aes' ) )
    cmd.add_argument( '--key-file', type=Path )
    cmd.add_argument( '--output', type=Path )

    cmd = commands.add_parser( 'file-decrypt' )
    cmd.add_argument( 'path' )
    cmd.add_argument( 'key', nargs='?' )
    cmd.add_argument( '--key-file', type=Path )
    cmd.add_argument( '--output', type=Path )
    cmd.add_argument( '--legacy', action='store_true' )

    cmd = commands.add_parser( 'hide-text' )
    cmd.add_argument( 'path' )
    cmd.add_argument( 'text' )
    cmd.add_argument( '--output', type=Path )
    cmd = commands.add_parser( 'extract-text' )
    cmd.add_argument( 'path' )
    cmd = commands.add_parser( 'generate-key' )
    cmd.add_argument( 'cipher' )
    cmd = commands.add_parser( 'generate-password' )
    cmd.add_argument( 'length', type=int, nargs='?', default=16 )
    commands.add_parser( 'interactive' )

    for cmd in commands.choices.values( ):
        cmd.add_argument( 
            '--json',
            action='store_true',
            help='Print a machine-readable JSON result',
        )
        cmd.add_argument( 
            '--report',
            type=Path,
            help='Write JSON; may contain secrets and plaintext',
        )

    return parser


# Prompt for secrets only on a terminal; automation supplies them explicitly.
def GetKey( opts ):
    key = getattr( opts, 'key', None )
    key_file = getattr( opts, 'key_file', None )

    if key is not None and key_file:
        raise ValueError( 'Choose a positional key or --key-file, not both' )

    if key_file:
        key = ReadBytes( key_file, 4096 ).decode( 'utf-8' ).rstrip( '\r\n' )

    needs_key = opts.command == 'file-decrypt' or ( 
        opts.command == 'file-encrypt' and opts.cipher == 'aes'
    ) or ( 
        opts.command in ( 'encrypt', 'decrypt' )
        and ( opts.cipher == 'aes' or ( opts.cipher == 'fernet' and opts.command == 'decrypt' ) )
    )

    if key is None and needs_key:
        if not sys.stdin.isatty( ):
            raise ValueError( 'Supply --key-file for noninteractive encryption/decryption' )

        key = getpass.getpass( 'Key/password: ' )

        if opts.command in ( 'encrypt', 'file-encrypt' ):
            if key != getpass.getpass( 'Confirm password: ' ):
                raise ValueError( 'Passwords do not match' )

    return key


def RunCommand( tool, opts ):
    key = GetKey( opts )
    cmd = opts.command

    if cmd == 'encrypt':
        return tool.Encrypt( opts.text, opts.cipher, key )

    if cmd == 'decrypt':
        return tool.Decrypt( opts.text, opts.cipher, key, legacy=opts.legacy )

    if cmd == 'file-encrypt':
        return tool.EncFile( opts.path, opts.output, opts.cipher, key )

    if cmd == 'file-decrypt':
        return tool.DecFile( opts.path, opts.output, key, legacy=opts.legacy )

    if cmd == 'hide-text':
        return tool.HideText( opts.path, opts.text, opts.output )

    if cmd == 'extract-text':
        return tool.ExtractText( opts.path )

    if cmd == 'analyze':
        return tool.Analyze( opts.text )

    if cmd == 'brute':
        return tool.BruteForce( opts.text )

    if cmd == 'generate-key':
        return tool.GenKey( opts.cipher )

    return { 'success': True, 'password': tool.GenPassword( opts.length ) }


def Present( result, opts ):
    rendered = json.dumps( result, indent=2, ensure_ascii=True )
    saved = True

    if opts.report:
        try:
            WriteNew( opts.report, ( rendered + '\n' ).encode( 'utf-8' ) )
        except ( OSError, ValueError ) as exc:
            result = result | { 'report_error': str( exc ) }
            rendered = json.dumps( result, indent=2, ensure_ascii=True )
            saved = False

    if opts.json:
        print( rendered )

        return saved

    title = 'Operation failed' if 'error' in result else 'Crypto Analyzer result'

    if sys.stdout.isatty( ) and 'NO_COLOR' not in os.environ:
        color = '31' if 'error' in result else '36'
        title = f'\033[{color}m{title}\033[0m'

    print( title )

    for name, value in result.items( ):
        if name == 'success':
            continue

        if isinstance( value, ( list, dict ) ):
            text = json.dumps( value, indent=2, ensure_ascii=True )
        else:
            text = str( value )

        print( f'{name.replace( "_", " " ).title( )}: {text}' )

    return saved


def RunPrompt( ):
    tool = CryptoTool( )
    parser = BuildParser( )
    print( 'Crypto Analyzer. Type help for commands or quit to leave.' )

    while True:
        try:
            line = input( 'crypto-analyzer> ' ).strip( )

            if not line:
                continue

            if line.lower( ) in ( 'quit', 'exit', 'q' ):
                return 0

            if line.lower( ) == 'help':
                parser.print_help( )
                continue

            opts = parser.parse_args( tool._ParseCmd( line ) )

            if opts.command == 'interactive':
                continue

            Present( RunCommand( tool, opts ), opts )
        except SystemExit:
            continue
        except ( EOFError, KeyboardInterrupt ):
            print( '\nSession closed.' )
            return 0
        except ( OSError, ValueError, TypeError ) as exc:
            print( f'Error: {exc}. Check the input or use help.' )


def Main( args=None ):
    args = list( sys.argv[1:] if args is None else args )

    if not args:
        return RunPrompt( )

    opts = BuildParser( ).parse_args( args )

    if opts.command == 'interactive':
        return RunPrompt( )

    try:
        result = RunCommand( CryptoTool( ), opts )
        saved = Present( result, opts )

        if not saved:
            return 2

        return 1 if 'error' in result else 0
    except KeyboardInterrupt:
        print( 'Operation cancelled.', file=sys.stderr )
        return 130
    except ( OSError, ValueError, TypeError ) as exc:
        if opts.json:
            print( json.dumps( { 'error': str( exc ) } ) )
        else:
            print( f'Error: {exc}. Check paths and arguments; use --help.', file=sys.stderr )

        return 2


if __name__ == '__main__':
    sys.exit( Main( ) )
