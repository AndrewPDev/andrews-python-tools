"""
Author: Andrew Piggot

Purpose: Verify Digital Conscience's analysis, reports, interactive commands, and CLI
behavior using isolated temporary files and regression fixtures.

Usage: Run from the project root:
    python -B -m unittest discover -s code_quality -p "test_*.py" -v
    python -B code_quality/test_conscience.py

    Discovery runs the code_quality test suite; -v displays individual test results.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from digital_conscience import CheckOutput, ColorText, ConscienceTool, ExitCode, Main, Render


# Exercise syntax accuracy, scan boundaries, reports, and CLI behavior.
class ReviewTests( unittest.TestCase ):
    # Verify set up behavior and expected results.
    def SetUp( self ):
        self.tmp = tempfile.TemporaryDirectory( )

        self.addCleanup( self.tmp.cleanup )

        self.root = Path( self.tmp.name )

    setUp = SetUp

    # Verify write behavior and expected results.
    def Write( self, name, source ):
        path = self.root / name

        path.parent.mkdir( parents=True, exist_ok=True )
        path.write_text( source, encoding='utf-8' )

        return path

    # Verify review behavior and expected results.
    def Review( self, source, **opts ):
        return ConscienceTool( **opts ).Scan( self.Write( 'sample.py', source ) )

    # Verify ids behavior and expected results.
    def Ids( self, report ):
        return [item['rule'] for item in report['findings']]

    # Verify docstrings behavior and expected results.
    def TestDocstrings( self ):
        report = self.Review( 'class Demo:\n    """Documented."""\n    async def Run( self ):\n        """Documented."""\n        return 1\n' )

        self.assertEqual( self.Ids( report ), [] )

        report = self.Review( 'class Demo:\n    """Documented."""\n    def Run( self ):\n        return 1\n' )

        self.assertEqual( self.Ids( report ), ['no_docstring'] )
        self.assertEqual( report['findings'][0]['line'], 3 )

    # Verify handlers and strings behavior and expected results.
    def TestHandlersAndStrings( self ):
        report = self.Review( 'text = "except: pass # TODO"\ntry:\n    Run()\nexcept ValueError:\n    pass\n' )

        self.assertEqual( self.Ids( report ), ['empty_except'] )

        report = self.Review( 'try:\n    Run()\nexcept:\n    Log()\n' )

        self.assertEqual( self.Ids( report ), ['bare_except'] )

    # Verify sql behavior and expected results.
    def TestSql( self ):
        report = self.Review( 'cursor.execute( "SELECT * FROM users WHERE name = %s", ( name, ) )\n' )

        self.assertEqual( self.Ids( report ), [] )

        for query in (
            'f"SELECT {name}"',
            '"SELECT %s" % name',
            '"SELECT " + name',
            '"SELECT {}".format( name )',
        ):
            with self.subTest( query=query ):
                report = self.Review( f'cursor.execute( { query } )\n' )

                self.assertEqual( self.Ids( report ), ['sql_format'] )

    # Verify defaults behavior and expected results.
    def TestDefaults( self ):
        report = self.Review( 'async def Run( data=[], *, opts={} ):\n    """Example."""\n    pass\n' )

        self.assertEqual( self.Ids( report ), ['mutable_default', 'mutable_default'] )

        report = self.Review( 'run = lambda data=[]: data\n' )

        self.assertEqual( self.Ids( report ), ['mutable_default'] )

    # Verify performance behavior and expected results.
    def TestPerformance( self ):
        report = self.Review( 'for row in rows:\n    sorted( values )\n    cursor.execute( query )\n    if row in [1, 2, 3]:\n        pass\nresult = sum( [item for item in rows] )\n' )

        self.assertEqual(
            set( self.Ids( report ) ),
            { 'loop_sort', 'loop_io', 'loop_membership', 'eager_reduce' },
        )

    # Verify loop boundaries behavior and expected results.
    def TestLoopBoundaries( self ):
        report = self.Review( 'for row in sorted( rows ):\n    def Run():\n        """Runs separately."""\n        return sorted( rows )\nelse:\n    sorted( rows )\n' )

        self.assertEqual( self.Ids( report ), [] )

        report = self.Review( 'result = [sorted( row ) for row in rows]\nwhile item in [1, 2]:\n    break\n' )

        self.assertEqual( self.Ids( report ), ['loop_sort', 'loop_membership'] )

    # Verify comments and suppression behavior and expected results.
    def TestCommentsAndSuppression( self ):
        report = self.Review( '# TODO: document this\ntext = "# FIXME"\nfor row in rows:\n    sorted( row ) # dc: ignore[loop_sort] -- row changes\n' )

        self.assertEqual( self.Ids( report ), ['todo_fixme'] )

        report = self.Review( 'for row in rows:\n    sorted( row ); text = "# dc: ignore[loop_sort]"\n' )

        self.assertEqual( self.Ids( report ), ['loop_sort'] )

    # Verify definition time calls behavior and expected results.
    def TestDefinitionTimeCalls( self ):
        report = self.Review( 'for row in rows:\n'
            '    def Run( data=sorted( row ) ):\n'
            '        """Defaults execute when defined."""\n'
            '        return sorted( data )\n'
            '    class Demo:\n'
            '        """Class bodies also execute when defined."""\n'
            '        data = sorted( row )\n' )

        self.assertEqual( self.Ids( report ), ['loop_sort', 'loop_sort'] )
        self.assertEqual( [item['line'] for item in report['findings']], [2, 7] )

    # Verify filters behavior and expected results.
    def TestFilters( self ):
        source = 'def Run( data=[] ):\n    for row in data:\n        sorted( row )\n'

        self.assertEqual( self.Ids( self.Review( source, categories=['performance'] ) ), ['loop_sort'] )
        self.assertEqual( self.Ids( self.Review( source, severity='high' ) ), ['mutable_default'] )
        self.assertEqual( self.Ids( self.Review( source, rules=['no_docstring'] ) ), ['no_docstring'] )
        self.assertEqual( self.Ids( self.Review( source, rules=[] ) ), [] )

        for opts in ( { 'rules': ['unknown'] }, { 'categories': ['unknown'] }, { 'max_line': 0 } ):
            with self.subTest( opts=opts ), self.assertRaises( ValueError ):
                ConscienceTool( **opts )

    # Verify scan errors and exclusions behavior and expected results.
    def TestScanErrorsAndExclusions( self ):
        self.Write( 'ok.py', 'value = 1\n' )
        self.Write( 'broken.py', 'def broken(\n' )
        self.Write( '.venv/skip.py', 'def broken(\n' )
        self.Write( 'generated/skip.py', 'def broken(\n' )
        self.Write( 'other.js', 'not python' )

        report = ConscienceTool( exclude=['generated'] ).Scan( self.root )

        self.assertEqual( report['summary']['files_found'], 2 )
        self.assertEqual( report['summary']['files_scanned'], 1 )
        self.assertEqual( report['summary']['files_failed'], 1 )
        self.assertEqual( report['summary']['entries_skipped'], 2 )
        self.assertEqual( ExitCode( report, 'none' ), 2 )
        self.assertTrue( ConscienceTool( ).Scan( self.root / 'missing' )['errors'] )
        self.assertTrue( ConscienceTool( ).Scan( self.root / 'other.js' )['errors'] )

    # Verify read error behavior and expected results.
    def TestReadError( self ):
        from unittest.mock import patch

        path = self.Write( 'denied.py', '' )

        with patch( 'digital_conscience.tokenize.open', side_effect=PermissionError( 'denied' ) ):
            report = ConscienceTool( ).Scan( path )

        self.assertEqual( report['summary']['files_scanned'], 0 )
        self.assertIn( 'denied', report['errors'][0]['message'] )

    # Verify encoding and unicode columns behavior and expected results.
    def TestEncodingAndUnicodeColumns( self ):
        path = self.root / 'encoded.py'

        path.write_bytes( b'# coding: latin-1\nname = "caf\xe9"\n' )
        self.assertEqual( ConscienceTool( ).Scan( path )['errors'], [] )

        report = self.Review( 'café = 1; result = sum( [x for x in rows] )\n' )

        self.assertEqual( report['findings'][0]['column'], 20 )

    # Verify fresh reports and no execution behavior and expected results.
    def TestFreshReportsAndNoExecution( self ):
        checker = ConscienceTool( )

        checker.Scan( self.Write( 'first.py', 'def Run():\n    pass\n' ) )

        report = checker.Scan( self.Write( 'second.py', 'raise RuntimeError( "must not execute" )\n' ) )

        self.assertEqual( report['summary']['files_scanned'], 1 )
        self.assertEqual( report['findings'], [] )
        self.assertEqual( report['errors'], [] )

    # Verify cli json and exit codes behavior and expected results.
    def TestCliJsonAndExitCodes( self ):
        path = self.Write( 'with spaces.py', 'def Run( data=[] ):\n    pass\n' )
        output = io.StringIO( )

        with contextlib.redirect_stdout( output ):
            status = Main( ['scan', str( path ), '--format', 'json'] )

        self.assertEqual( status, 1 )

        report = json.loads( output.getvalue( ) )

        self.assertEqual( report['schema_version'], 1 )
        self.assertEqual( ExitCode( report, 'none' ), 0 )

        for mode in ( 'mentor', 'intern', 'coach' ):
            self.assertIn( report['findings'][0]['advice'], Render( report, mode ) )

        dest = self.root / 'report.json'

        self.assertEqual(
            Main( [
                'scan',
                str( path ),
                '--output',
                str( dest ),
                '--format',
                'json',
                '--fail-on',
                'none',
            ] ),
            0,
        )
        self.assertEqual( json.loads( dest.read_text( ) )['summary'], report['summary'] )

        original = path.read_text( )

        with contextlib.redirect_stderr( io.StringIO( ) ):
            self.assertEqual( Main( ['scan', str( path ), '--output', str( path )] ), 2 )

        self.assertEqual( path.read_text( ), original )

    # Verify rating weights and prevent empty or failed scans from receiving a clean score.
    def TestRating( self ):
        report = self.Review( 'def Run( data=[] ):\n    "Documented."\n    pass\n' )

        self.assertEqual( report['rating']['score'], 8.0 )
        self.assertEqual( self.Review( 'value = 1' )['rating']['score'], 10.0 )
        self.assertIsNone( self.Review( 'def broken(' )['rating']['score'] )
        self.assertIsNone( self.Review( '', rules=[] )['rating']['score'] )

        empty = self.root / 'empty'

        empty.mkdir( )
        self.assertIsNone( ConscienceTool( ).Scan( empty )['rating']['score'] )

    # Exercise interactive scan, quoted paths, export, mode changes, and recoverable errors.
    def TestPrompt( self ):
        from unittest.mock import patch

        path = self.Write( 'sample file.py', 'value = 1\n' )
        dest = self.root / 'report file.json'
        cmds = [
            'report',
            'mode invalid',
            'help',
            f'scan "{ path }"',
            'mode coach',
            'report',
            f'export "{ dest }"',
            'unknown',
            'quit',
        ]
        output = io.StringIO( )

        with patch( 'builtins.input', side_effect=cmds ), contextlib.redirect_stdout( output ):
            self.assertEqual( Main( [] ), 0 )

        self.assertEqual( json.loads( dest.read_text( ) )['rating']['score'], 10.0 )
        self.assertIn( 'Run scan <path> first', output.getvalue( ) )
        self.assertIn( 'Unknown command', output.getvalue( ) )

        for exc in ( EOFError, KeyboardInterrupt ):
            with patch( 'builtins.input', side_effect=exc ), contextlib.redirect_stdout( io.StringIO( ) ):
                self.assertEqual( Main( ['interactive'] ), 0 )

    # Reject parent traversal, source extensions, and aliases while allowing explicit report paths.
    def TestOutputPaths( self ):
        target = self.Write( 'sample.py', '' )

        for dest in ( self.root / '..' / 'report.json', self.root / 'other.pyw', target ):
            with self.subTest( dest=dest ), self.assertRaises( ValueError ):
                CheckOutput( dest, target )

        CheckOutput( self.root / 'report.json', target )

    # Keep redirected text plain and honor NO_COLOR in interactive terminals.
    def TestColor( self ):
        from unittest.mock import patch

        text = 'SUMMARY\n[high/high confidence] example'

        with patch( 'sys.stdout.isatty', return_value=False ):
            self.assertEqual( ColorText( text ), text )

        with patch( 'sys.stdout.isatty', return_value=True ), patch.dict( 'os.environ', { 'NO_COLOR': '1' } ):
            self.assertEqual( ColorText( text ), text )


# unittest requires lowercase hooks; implementation names follow project style.
# Discover PascalCase Test methods through the standard unittest hook.
def LoadTests( loader, tests, pattern ):
    loader.testMethodPrefix = 'Test'

    return loader.loadTestsFromTestCase( ReviewTests )


load_tests = LoadTests


if __name__ == '__main__':
    unittest.main( )
