"""
Author: Andrew Piggot

Purpose: Verify CSV parsing, conservative analysis, lossless exports, cleaning previews,
error recovery, and command-line behavior with isolated synthetic fixtures.

Usage: python -B -m unittest discover -s csv_main -p "test_*.py" -v
    Run from the project root. No third-party dependencies are needed.
"""

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import csv_analyzer as analyzer


class CSVTests( unittest.TestCase ):
    def SetUp( self ):
        self.tmp = tempfile.TemporaryDirectory( )
        self.addCleanup( self.tmp.cleanup )
        self.root = Path( self.tmp.name )
        self.tool = analyzer.CSVTool( )

    setUp = SetUp

    def Write( self, text, name='data.csv', encoding='utf-8' ):
        path = self.root / name
        path.write_bytes( text.encode( encoding ) )

        return path

    def TestQuotedAndMultiline( self ):
        path = self.Write( 'name,note\nAlice,"one,two"\nBob,"first\nsecond"\n' )
        self.assertTrue( self.tool.Load( path ) )
        self.assertEqual( self.tool.data, [ [ 'Alice', 'one,two' ], [ 'Bob', 'first\nsecond' ] ] )
        self.assertTrue( self.tool.Export( self.root / 'copy.csv' ) )
        copy = analyzer.CSVTool( )
        self.assertTrue( copy.Load( self.root / 'copy.csv' ) )
        self.assertEqual( copy.data, self.tool.data )

    def TestDelimitersAndEncoding( self ):
        for sep in ( ';', '\t', '|' ):
            path = self.Write( f'name{sep}value\nAlice{sep}10\nBob{sep}20\n' )
            self.assertTrue( self.tool.Load( path ) )
            self.assertEqual( self.tool.delimiter, sep )
            self.assertEqual( self.tool.headers, [ 'name', 'value' ] )

        path = self.Write( 'name,value\ncaf\u00e9,10\n', encoding='utf-8-sig' )
        self.assertTrue( self.tool.Load( path ) )
        self.assertEqual( self.tool.headers[0], 'name' )
        path = self.Write( 'name,value\ncaf\u00e9,10\n', encoding='cp1252' )
        self.assertFalse( self.tool.Load( path ) )
        self.assertTrue( self.tool.Load( path, encoding='cp1252' ) )

    def TestHeaderOnlyAndSingleColumn( self ):
        self.assertTrue( self.tool.Load( self.Write( 'name\n' ) ) )
        report = self.tool.GetReport( )
        self.assertEqual( report['summary']['rows'], 0 )
        self.assertIsNone( report['summary']['completeness_percent'] )
        self.assertTrue( self.tool.Clean( { 'remove_duplicates': True } ) )
        self.assertTrue( self.tool.Export( self.root / 'headers.csv' ) )
        self.assertTrue( self.tool.Load( self.Write( 'name\nAlice\nBob\n' ) ) )
        self.assertEqual( len( self.tool.data ), 2 )

    def TestLoadIsTransactional( self ):
        path = self.Write( 'a,b\n1,2\n' )
        self.assertTrue( self.tool.Load( path ) )
        original = ( self.tool.filename, list( self.tool.data ), list( self.tool.headers ) )

        for text in ( '', 'a,b\n"unterminated', '\0bad' ):
            self.assertFalse( self.tool.Load( self.Write( text, 'bad.csv' ) ) )
            self.assertTrue( self.tool.error )
            self.assertEqual( original, ( self.tool.filename, self.tool.data, self.tool.headers ) )

        self.assertFalse( self.tool.Load( self.root / 'missing.csv' ) )
        self.assertFalse( self.tool.Load( path, delimiter='too long' ) )
        self.assertFalse( self.tool.Load( self.root / 'book.xlsx' ) )

    def TestDuplicatesRespectBoundaries( self ):
        path = self.Write( 'x,y\n"a,b",c\na,"b,c"\n"a,b",c\n' )
        self.assertTrue( self.tool.Load( path ) )
        self.assertEqual( self.tool.GetReport( )['quality']['duplicate_rows'], 1 )
        self.assertTrue( self.tool.Clean( { 'remove_duplicates': True } ) )
        self.assertEqual( self.tool.data, [ [ 'a,b', 'c' ], [ 'a', 'b,c' ] ] )

    def TestRaggedAndHeaders( self ):
        path = self.Write( 'x,x,\n1,2\n3,4,5,EXTRA\n' )
        self.assertTrue( self.tool.Load( path, delimiter=',' ) )
        report = self.tool.GetReport( )
        self.assertEqual( report['quality']['ragged_rows'], 2 )
        self.assertEqual( report['quality']['duplicate_headers'], [ 'x' ] )
        self.assertEqual( report['quality']['blank_headers'], [ 3 ] )
        self.assertEqual( report['columns'][3]['samples'], [ 'EXTRA' ] )
        self.assertEqual( report['columns'][3]['missing_cells'], 1 )
        self.assertTrue( self.tool.Export( self.root / 'ragged.csv' ) )
        copy = analyzer.CSVTool( )
        self.assertTrue( copy.Load( self.root / 'ragged.csv', delimiter=',' ) )
        self.assertEqual( copy.data, self.tool.data )

    def TestConservativeTypes( self ):
        for values in ( [ '001', '002' ], [ 'NaN', 'inf' ], [ '1,23' ], [ '1', 'oops' ] ):
            self.assertEqual( self.tool._GuessType( values ), 'Text' )

        self.assertEqual( self.tool._GuessType( [ '2024-02-29', '2023-01-01' ] ), 'Date/Time' )
        self.assertEqual( self.tool._GuessType( [ '01/02/2024' ] ), 'Text' )
        self.assertFalse( self.tool._IsDate( '2023-02-29' ) )
        path = self.Write( 'n\n0.1\n0.2\n' )
        self.assertTrue( self.tool.Load( path ) )
        self.assertEqual( self.tool.GetReport( )['columns'][0]['numeric']['mean'], '0.15' )

    def TestPreviewMatchesCleaning( self ):
        path = self.Write( 'a,b\n x , y \nx,y\n , \n@@,!!\n' )
        self.assertTrue( self.tool.Load( path, delimiter=',' ) )
        before = [ list( row ) for row in self.tool.data ]
        options = dict.fromkeys( analyzer.CLEAN_FLAGS, True )
        planned, summary = self.tool.PlanClean( options )
        self.assertTrue( self.tool.Clean( options, dry_run=True ) )
        self.assertEqual( self.tool.data, before )
        self.assertTrue( self.tool.Clean( options ) )
        self.assertEqual( self.tool.data, planned )
        self.assertEqual( planned, [ [ 'x', 'y' ] ] )
        self.assertEqual( self.tool.last_clean, summary )
        self.assertEqual( summary['empty_rows_removed'], 2 )
        self.assertFalse( self.tool.Clean( { 'unknown': True } ) )
        self.assertFalse( self.tool.Clean( { 'trim_whitespace': 'yes' } ) )

    def TestNoImplicitCleaning( self ):
        self.assertTrue( self.tool.Load( self.Write( 'id,email\n001, a+b@example.com \n' ) ) )
        before = [ list( row ) for row in self.tool.data ]
        self.assertTrue( self.tool.Clean( {} ) )
        self.assertEqual( self.tool.data, before )

    def TestOverwriteAndFormulaEscaping( self ):
        source = self.Write( 'name,value\nAlice,=1+1\nBob,-12\n' )
        original = source.read_bytes( )
        self.assertTrue( self.tool.Load( source ) )
        self.assertEqual( self.tool.GetReport( )['quality']['formula_like_cells'], 2 )
        self.assertFalse( self.tool.Export( source ) )
        self.assertEqual( source.read_bytes( ), original )
        self.assertFalse( self.tool.Export( self.root / '..' / 'escape.csv' ) )
        dest = self.root / 'safe.csv'
        self.assertTrue( self.tool.Export( dest, safe_excel=True ) )

        with dest.open( newline='' ) as handle:
            rows = list( csv.reader( handle ) )

        self.assertEqual( rows[1][1], "'=1+1" )
        self.assertEqual( rows[2][1], "'-12" )
        self.assertEqual( self.tool.data[1][1], '-12' )

    def TestLimits( self ):
        path = self.Write( 'a,b\n1,2\n3,4\n' )

        with patch.object( analyzer, 'MAX_ROWS', 1 ):
            self.assertFalse( self.tool.Load( path ) )

        with patch.object( analyzer, 'MAX_CELLS', 3 ):
            self.assertFalse( self.tool.Load( path ) )

        with patch.object( analyzer, 'MAX_BYTES', 3 ):
            self.assertFalse( self.tool.Load( path ) )

    def TestCliPreviewAndExport( self ):
        source = self.Write( 'a,b\n x , y \nx,y\n' )
        output = io.StringIO( )

        with contextlib.redirect_stdout( output ):
            status = analyzer.Main( [ 'clean', str( source ), '--trim', '--dedupe', '--dry-run', '--json' ] )

        self.assertEqual( status, 0 )
        report = json.loads( output.getvalue( ) )
        self.assertEqual( report['preview']['rows_after'], 1 )
        self.assertEqual( report['summary']['rows'], 2 )
        self.assertIn( 'CLEANING PREVIEW', analyzer.Render( report ) )
        dest = self.root / 'out.csv'

        with contextlib.redirect_stdout( io.StringIO( ) ):
            self.assertEqual(
                analyzer.Main( [ 'clean', str( source ), '--trim', '--dedupe', '--output', str( dest ) ] ),
                0,
            )
            self.assertEqual( analyzer.Main( [ 'clean', str( source ) ] ), 2 )

        self.assertTrue( dest.exists( ) )

    def TestInteractiveAndReports( self ):
        source = self.Write( 'a,b\n1,2\n', name='with spaces.csv' )
        report = self.root / 'report.json'
        commands = [ f'load "{source}"', 'analyze', f'report "{report}"', 'quit' ]

        with patch( 'builtins.input', side_effect=commands ):
            with contextlib.redirect_stdout( io.StringIO( ) ):
                self.assertEqual( analyzer.Main( [] ), 0 )

        self.assertEqual( json.loads( report.read_text( ) )['summary']['rows'], 1 )
        self.assertEqual(
            analyzer.ParseCommand( 'load "C:\\My Files\\data.csv"' )[1],
            'C:\\My Files\\data.csv',
        )
        self.assertIs( analyzer.main, analyzer.Main )


# unittest's discovery hook is externally named; test implementations use PascalCase.
def LoadTests( loader, tests, pattern ):
    loader.testMethodPrefix = 'Test'

    return loader.loadTestsFromTestCase( CSVTests )


load_tests = LoadTests


if __name__ == '__main__':
    unittest.main( )
