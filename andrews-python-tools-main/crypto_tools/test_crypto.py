"""
Author: Andrew Piggot

Purpose: Verify crypto round trips, authentication, legacy recovery, safe file output,
Unicode handling, optional dependencies, steganography, and CLI behavior.

Usage: python -B -m unittest discover -s crypto_tools -p "test_*.py" -v
    Run from the project root. Cryptography/Pillow tests skip when dependencies are absent.
"""

import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import crypto_analyzer as crypto


class CryptoTests( unittest.TestCase ):
    def SetUp( self ):
        self.tmp = tempfile.TemporaryDirectory( )
        self.addCleanup( self.tmp.cleanup )
        self.root = Path( self.tmp.name )
        self.tool = crypto.CryptoTool( )

    setUp = SetUp

    def TestClassicalUnicode( self ):
        text = 'Hello, caf\u00e9 \u4e16\u754c!'

        for cipher, key in ( 
            ( 'caesar', '-29' ),
            ( 'vigenere', 'KEY' ),
            ( 'atbash', None ),
            ( 'rot13', None ),
            ( 'base64', None ),
            ( 'hex', None ),
            ( 'binary', None ),
            ( 'xor', 's\u00e9cret' ),
        ):
            with self.subTest( cipher=cipher ):
                encoded = self.tool.Encrypt( text, cipher, key )
                self.assertNotIn( 'error', encoded )
                decoded = self.tool.Decrypt( encoded['output'], cipher, key )
                self.assertEqual( decoded['output'], text )

    def TestKnownVectors( self ):
        self.assertEqual( 
            self.tool.Encrypt( 'ATTACKATDAWN', 'vigenere', 'LEMON' )['output'],
            'LXFOPVEFRNHR',
        )
        self.assertEqual( self.tool.Encrypt( 'Hello', 'base64' )['output'], 'SGVsbG8=' )
        self.assertEqual( 
            self.tool.Encrypt( 'SOS 123', 'morse' )['output'],
            '... --- ... / .---- ..--- ...--',
        )
        self.assertEqual( self.tool.Decrypt( '... --- ...', 'morse' )['output'], 'SOS' )

    def TestInvalidInputs( self ):
        for cipher, text, key in ( 
            ( 'base64', 'SGVsbG8=!', None ),
            ( 'hex', 'zz', None ),
            ( 'binary', '101', None ),
            ( 'vigenere', 'abc', '123' ),
            ( 'substitution', 'abc', None ),
            ( 'xor', 'abc', '' ),
            ( 'morse', '.- unknown', None ),
        ):
            with self.subTest( cipher=cipher ):
                self.assertIn( 'error', self.tool.Decrypt( text, cipher, key ) )

        for length in ( 0, -1, 1025, True ):
            with self.assertRaises( ValueError ):
                self.tool.GenPassword( length )

    def TestSubstitution( self ):
        result = self.tool.Encrypt( 'Hello World!', 'substitution' )
        decoded = self.tool.Decrypt( 
            result['output'],
            'substitution',
            substitution_key=result['key'],
        )
        self.assertEqual( decoded['output'], 'Hello World!' )
        self.assertIn( 'error', self.tool.Encrypt( 'abc', 'substitution', 'A' * 26 ) )

    @unittest.skipUnless( crypto.CRYPTO_AVAILABLE, 'cryptography not installed' )
    def TestAuthenticatedRoundTrips( self ):
        for cipher in ( 'aes', 'fernet' ):
            with self.subTest( cipher=cipher ):
                first = self.tool.Encrypt( 'Unicode \u4e16\u754c \u00e9', cipher )
                self.assertNotIn( 'error', first )
                key = first['key']
                second = self.tool.Encrypt( first['input'], cipher, key )
                self.assertNotEqual( first['output'], second['output'] )
                self.assertEqual( 
                    self.tool.Decrypt( first['output'], cipher, key )['output'],
                    first['input'],
                )
                wrong = self.tool.GenKey( cipher )['key']
                self.assertIn( 'error', self.tool.Decrypt( first['output'], cipher, wrong ) )
                damaged = bytearray( crypto.Decode64( first['output'], url=True ) )
                damaged[-1] ^= 1
                token = base64.urlsafe_b64encode( damaged ).decode( 'ascii' )
                self.assertIn( 'error', self.tool.Decrypt( token, cipher, key ) )

    @unittest.skipUnless( crypto.CRYPTO_AVAILABLE, 'cryptography not installed' )
    def TestStandardAndLegacyFernet( self ):
        key = crypto.Fernet.generate_key( )
        token = crypto.Fernet( key ).encrypt( b'legacy' )
        old_key = base64.urlsafe_b64encode( key ).decode( 'ascii' )
        old_token = base64.urlsafe_b64encode( token ).decode( 'ascii' )
        self.assertEqual( self.tool.Decrypt( old_token, 'fernet', old_key )['output'], 'legacy' )
        result = self.tool.Encrypt( 'standard', 'fernet', key.decode( 'ascii' ) )
        self.assertEqual( crypto.Fernet( key ).decrypt( result['output'].encode( ) ), b'standard' )

    @unittest.skipUnless( crypto.CRYPTO_AVAILABLE, 'cryptography not installed' )
    def TestLegacyAes( self ):
        salt, iv = b's' * 16, b'i' * 16
        kdf = crypto.PBKDF2HMAC( 
            algorithm=crypto.hashes.SHA256( ),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        cipher = crypto.Cipher( 
            crypto.algorithms.AES( kdf.derive( b'password' ) ),
            crypto.modes.CBC( iv ),
        )
        encryptor = cipher.encryptor( )
        padder = crypto.padding.PKCS7( 128 ).padder( )
        padded = padder.update( b'legacy text' ) + padder.finalize( )
        token = base64.b64encode( salt + iv + encryptor.update( padded ) + encryptor.finalize( ) ).decode( )
        self.assertIn( 'error', self.tool.Decrypt( token, 'aes', 'password' ) )
        self.assertEqual( 
            self.tool.Decrypt( token, 'aes', 'password', legacy=True )['output'],
            'legacy text',
        )

    @unittest.skipUnless( crypto.CRYPTO_AVAILABLE, 'cryptography not installed' )
    def TestBinaryFilesAndNoEmbeddedKeys( self ):
        source = self.root / 'source.bin'
        source.write_bytes( bytes( range( 256 ) ) )

        for cipher in ( 'aes', 'fernet' ):
            encrypted = self.root / ( cipher + '.encrypted' )
            result = self.tool.EncFile( source, encrypted, cipher )
            self.assertNotIn( 'error', result )
            envelope = json.loads( encrypted.read_text( ) )
            self.assertNotIn( 'key', envelope )
            self.assertNotIn( result['key'], encrypted.read_text( ) )
            self.assertIn( 'error', self.tool.DecFile( encrypted ) )
            decoded = self.tool.DecFile( encrypted, password=result['key'] )
            self.assertEqual( Path( decoded['output_file'] ).read_bytes( ), source.read_bytes( ) )
            self.assertIn( 'error', self.tool.EncFile( source, encrypted, cipher ) )
            self.assertIn( 'error', self.tool.DecFile( encrypted, source, result['key'] ) )
            self.assertEqual( source.read_bytes( ), bytes( range( 256 ) ) )

    @unittest.skipUnless( crypto.CRYPTO_AVAILABLE, 'cryptography not installed' )
    def TestMetadataCannotChoosePaths( self ):
        source = self.root / 'old.json'
        encoded = self.tool.Encrypt( base64.b64encode( b'recovered' ).decode( ), 'fernet' )
        source.write_text( json.dumps( {
            'original_file': '../../escaped.txt',
            'key': encoded['key'],
            'cipher_type': 'fernet',
            'encrypted_content': encoded['output'],
        } ) )
        self.assertIn( 'error', self.tool.DecFile( source, legacy=True ) )
        result = self.tool.DecFile( source, password=encoded['key'], legacy=True )
        self.assertEqual( Path( result['output_file'] ).parent, self.root )
        self.assertEqual( Path( result['output_file'] ).read_bytes( ), b'recovered' )

    def TestPathsAndLimits( self ):
        path = self.root / 'data'
        crypto.WriteNew( path, b'original' )

        with self.assertRaises( FileExistsError ):
            crypto.WriteNew( path, b'changed' )

        with self.assertRaises( ValueError ):
            crypto.WriteNew( self.root / '..' / 'outside', b'bad' )

        with self.assertRaises( ValueError ):
            crypto.ReadBytes( path, 2 )

        self.assertEqual( path.read_bytes( ), b'original' )

    @unittest.skipUnless( crypto.STEGANOGRAPHY_AVAILABLE, 'Pillow not installed' )
    def TestSteganography( self ):
        source = self.root / 'cover.png'
        crypto.Image.new( 'RGB', ( 40, 40 ), 'white' ).save( source )
        message = 'Hidden \u4e16\u754c \u00e9'
        result = self.tool.HideText( source, message )
        self.assertNotIn( 'error', result )
        self.assertEqual( 
            self.tool.ExtractText( result['output_image'] )['extracted_text'],
            message,
        )
        self.assertIn( 'error', self.tool.HideText( source, 'x' * 1000 ) )
        self.assertIn( 'error', self.tool.HideText( source, message, self.root / 'bad.jpg' ) )
        self.assertIn( 'error', self.tool.ExtractText( source ) )
        image = self.tool.LoadImage( result['output_image'] )
        pixels = bytearray( image.tobytes( ) )
        pixels[41 * 8] ^= 1
        crypto.Image.frombytes( 'RGB', image.size, bytes( pixels ) ).save( self.root / 'bad.png' )
        self.assertIn( 'error', self.tool.ExtractText( self.root / 'bad.png' ) )

    def TestOptionalDependencies( self ):
        with patch.object( crypto, 'CRYPTO_AVAILABLE', False ):
            self.assertIn( 'error', self.tool.Encrypt( 'text', 'aes', 'password' ) )
            self.assertEqual( self.tool.Encrypt( 'abc', 'caesar' )['output'], 'def' )

        with patch.object( crypto, 'STEGANOGRAPHY_AVAILABLE', False ):
            self.assertIn( 'error', self.tool.HideText( 'missing.png', 'text' ) )

    def TestAnalysisAndBrute( self ):
        self.assertEqual( self.tool.Analyze( '' )['analysis']['possible_ciphers'], [] )
        self.assertEqual( self.tool.Analyze( '' )['analysis']['entropy_bits_per_byte'], 0 )
        results = self.tool.BruteForce( 'Khoor Zruog' )['results']
        self.assertEqual( len( results ), 26 )
        self.assertIn( 'Hello World', [ row['decrypted'] for row in results ] )
        self.assertTrue( all( 0 <= row['readable_score'] <= 10 for row in results ) )

    def TestCliAndParsing( self ):
        output = io.StringIO( )

        with contextlib.redirect_stdout( output ):
            status = crypto.Main( [ 'encrypt', 'base64', 'Hello', '--json' ] )

        self.assertEqual( status, 0 )
        self.assertEqual( json.loads( output.getvalue( ) )['output'], 'SGVsbG8=' )
        self.assertEqual( 
            self.tool._ParseCmd( 'file-encrypt "C:\\My Files\\doc.txt"' )[1],
            'C:\\My Files\\doc.txt',
        )

        with self.assertRaises( ValueError ):
            self.tool._ParseCmd( 'encrypt caesar "unfinished' )

        with patch( 'builtins.input', side_effect=[ 'help', 'encrypt caesar "Hello" 3', 'quit' ] ):
            with contextlib.redirect_stdout( io.StringIO( ) ):
                self.assertEqual( crypto.Main( [] ), 0 )

    @unittest.skipUnless( crypto.CRYPTO_AVAILABLE, 'cryptography not installed' )
    def TestEmptyAndMalformedCiphertext( self ):
        for cipher in ( 'aes', 'fernet' ):
            result = self.tool.Encrypt( '', cipher )
            decoded = self.tool.Decrypt( result['output'], cipher, result['key'] )
            self.assertEqual( decoded['output'], '' )

        result = self.tool.Encrypt( 'message', 'aes', 'password' )
        data = bytearray( crypto.Decode64( result['output'] ) )

        for offset in ( 8, 24, 36 ):
            changed = data.copy( )
            changed[offset] ^= 1
            token = base64.b64encode( changed ).decode( 'ascii' )
            self.assertIn( 'error', self.tool.Decrypt( token, 'aes', 'password' ) )

        data[4:8] = ( 2**32 - 1 ).to_bytes( 4, 'big' )
        token = base64.b64encode( data ).decode( 'ascii' )
        self.assertIn( 'settings', self.tool.Decrypt( token, 'aes', 'password' )['error'] )

    @unittest.skipUnless( crypto.CRYPTO_AVAILABLE, 'cryptography not installed' )
    def TestFailedReportPreservesGeneratedKey( self ):
        source = self.root / 'plain.txt'
        source.write_text( 'recoverable' )
        report = self.root / 'existing.json'
        report.write_text( 'preserve' )
        output = io.StringIO( )

        with contextlib.redirect_stdout( output ):
            status = crypto.Main( 
                [ 'file-encrypt', str( source ), '--json', '--report', str( report ) ]
            )

        result = json.loads( output.getvalue( ) )
        self.assertEqual( status, 2 )
        self.assertIn( 'report_error', result )
        self.assertEqual( report.read_text( ), 'preserve' )
        decoded = self.tool.DecFile( result['output_file'], password=result['key'] )
        self.assertEqual( Path( decoded['output_file'] ).read_text( ), 'recoverable' )


# unittest requires this lowercase hook; test implementations retain PascalCase names.
def LoadTests( loader, tests, pattern ):
    loader.testMethodPrefix = 'Test'

    return loader.loadTestsFromTestCase( CryptoTests )


load_tests = LoadTests


if __name__ == '__main__':
    unittest.main( )
