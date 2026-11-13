"""
Author: Andrew Piggot

Purpose: Analyze delimited text, report data-quality issues, preview explicit cleaning
operations, and export new CSV files without overwriting source data.

Usage: Run from the project root:
    python csv_main/csv_analyzer.py
    python csv_main/csv_analyzer.py analyze csv_main/sample_data.csv --json
    python csv_main/csv_analyzer.py clean csv_main/sample_data.csv --trim --dedupe --dry-run
    python csv_main/csv_analyzer.py clean csv_main/sample_data.csv --trim --output cleaned.csv

    No arguments opens the interactive prompt. Use --help for delimiter, encoding,
    report, and cleaning options. This tool reads CSV/TSV text, not Excel workbooks.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shlex
import sys
from collections import Counter
from datetime import date, datetime, timezone
from decimal import Decimal, localcontext
from pathlib import Path


MAX_BYTES = 32 * 1024 * 1024
MAX_ROWS = 250_000
MAX_CELLS = 2_000_000
CLEAN_FLAGS = {
    'trim_whitespace',
    'remove_empty_rows',
    'remove_duplicates',
    'remove_special_chars',
}
NUMBER = re.compile( r'[+-]?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d{1,3})?' )


# Files are exclusively created; explicit output paths never overwrite existing data.
def WriteNew( path, text, encoding='utf-8' ):
    path = Path( path ).expanduser( )

    if '..' in path.parts:
        raise ValueError( 'Use an explicit output path without parent traversal (..)' )

    data = text.encode( encoding )
    descriptor = os.open( path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 )

    with os.fdopen( descriptor, 'wb' ) as handle:
        handle.write( data )


# Explicit delimiter selection takes priority over heuristic detection.
def GetDelimiter( value ):
    if value in ( 'tab', '\\t' ):
        return '\t'

    if not isinstance( value, str ) or len( value ) != 1 or value in '\r\n"\0':
        raise ValueError( 'Delimiter must be one character, such as comma, semicolon, pipe, or tab' )

    return value


class CSVTool:
    def __init__( self ):
        self.data = []
        self.headers = []
        self.filename = ''
        self.stats = {}
        self.error = ''
        self.loaded = False
        self.delimiter = ','
        self.encoding = 'utf-8-sig'
        self.file_size = 0
        self.warnings = []
        self.last_clean = {}

    # Parse into local state so a failed load cannot erase the previous dataset.
    def Load( self, filename, *, delimiter=None, encoding='utf-8-sig' ):
        try:
            path = Path( filename ).expanduser( )

            if path.suffix.lower( ) in ( '.xlsx', '.xls', '.xlsm' ):
                raise ValueError( 'Export the workbook to CSV first; Excel files are not supported' )

            with path.open( 'rb' ) as handle:
                raw = handle.read( MAX_BYTES + 1 )

            if len( raw ) > MAX_BYTES:
                raise ValueError( 'File exceeds the 32 MiB input limit' )

            text = raw.decode( encoding )

            if not text.strip( ):
                raise ValueError( 'The file is empty; a header record is required' )

            if '\0' in text:
                raise ValueError( 'NUL bytes found; select the correct text encoding' )

            warnings = []

            if delimiter is not None:
                separator = GetDelimiter( delimiter )
            else:
                try:
                    separator = csv.Sniffer( ).sniff( text[:65536], delimiters=',;\t|' ).delimiter
                except csv.Error:
                    first_line = text.splitlines( )[0]
                    try:
                        separator = csv.Sniffer( ).sniff( first_line, delimiters=',;\t|' ).delimiter
                    except csv.Error:
                        separator = ','

                    warnings.append( 'Delimiter detection was uncertain; verify it or use --delimiter.' )

            reader = csv.reader( io.StringIO( text, newline='' ), delimiter=separator, strict=True )
            headers = next( reader )

            if not headers:
                raise ValueError( 'The first record must contain column headers' )

            rows = []
            cells = len( headers )
            width = len( headers )

            if cells > MAX_CELLS:
                raise ValueError( 'Header exceeds the cell limit' )

            for row in reader:
                cells += len( row )
                width = max( width, len( row ) )

                if (
                    len( rows ) >= MAX_ROWS
                    or cells > MAX_CELLS
                    or ( len( rows ) + 1 ) * width > MAX_CELLS
                ):
                    raise ValueError( 'Dataset exceeds the 250,000-row or 2,000,000-cell limit' )

                rows.append( row )

            self.data = rows
            self.headers = headers
            self.filename = str( path.absolute( ) )
            self.delimiter = separator
            self.encoding = encoding
            self.file_size = len( raw )
            self.warnings = warnings
            self.stats = {}
            self.last_clean = {}
            self.error = ''
            self.loaded = True

            return True
        except ( OSError, UnicodeError, LookupError, ValueError, csv.Error, StopIteration ) as exc:
            self.error = f'Could not load {filename}: {exc}'

            return False

    # Infer conservatively: identifiers, mixed formats, infinities, and locale numbers stay text.
    def _GuessType( self, data ):
        values = [ value.strip( ) for value in data if value.strip( ) ]

        if not values:
            return 'Empty'

        if all( NUMBER.fullmatch( value ) and len( value ) <= 100 for value in values ):
            return 'Numeric'

        if all( self._IsDate( value ) for value in values ):
            return 'Date/Time'

        return 'Text'

    # Only unambiguous ISO dates/timestamps qualify; no day/month guessing or conversion.
    def _IsDate( self, value ):
        if not re.match( r'^\d{4}-\d{2}-\d{2}(?:$|[T ])', value ):
            return False

        try:
            if len( value ) == 10:
                date.fromisoformat( value )
            else:
                datetime.fromisoformat( value.replace( 'Z', '+00:00' ) )

            return True
        except ValueError:
            return False

    def ColStats( self, index, header ):
        values = [ row[index] if index < len( row ) else '' for row in self.data ]
        present = [ value for value in values if value.strip( ) ]
        unique = dict.fromkeys( present )
        kind = self._GuessType( present )
        info = {
            'index': index + 1,
            'name': header,
            'type': kind,
            'non_empty': len( present ),
            'empty': len( values ) - len( present ),
            'missing_cells': sum( index >= len( row ) for row in self.data ),
            'unique': len( unique ),
            'samples': list( unique )[:3],
        }

        if kind == 'Numeric':
            numbers = [ Decimal( value.strip( ) ) for value in present ]

            with localcontext( ) as ctx:
                ctx.prec = 128
                total = sum( numbers, Decimal( 0 ) )
                info['numeric'] = {
                    'min': str( min( numbers ) ),
                    'max': str( max( numbers ) ),
                    'mean': str( total / len( numbers ) ),
                }

        return info

    # Tuple keys distinguish commas inside cells from actual column boundaries.
    def GetReport( self ):
        if not self.loaded:
            return { 'error': 'Load a CSV file first' }

        width = max( [ len( self.headers ) ] + [ len( row ) for row in self.data ] )
        seen = set( )
        duplicates = []
        empty = []
        ragged = []
        spaced = 0
        formula_cells = 0

        for record, row in enumerate( self.data, 2 ):
            key = tuple( row )

            if key in seen:
                duplicates.append( record )

            seen.add( key )

            if not any( value.strip( ) for value in row ):
                empty.append( record )

            if len( row ) != len( self.headers ):
                ragged.append( record )

            spaced += sum( value != value.strip( ) for value in row )
            formula_cells += sum( self.IsFormula( value ) for value in row )

        names = Counter( name.strip( ) for name in self.headers )
        blanks = [ index + 1 for index, name in enumerate( self.headers ) if not name.strip( ) ]
        columns = [
            self.ColStats(
                index,
                self.headers[index] if index < len( self.headers ) else f'Extra column {index + 1}',
            )
            for index in range( width )
        ]
        total_cells = len( self.data ) * width
        missing = sum( column['empty'] for column in columns )
        completeness = round(
            100 * ( total_cells - missing ) / total_cells,
            2,
        ) if total_cells else None
        report = {
            'schema_version': 1,
            'file': self.filename,
            'generated_at': datetime.now( timezone.utc ).isoformat( ),
            'delimiter': self.delimiter,
            'encoding': self.encoding,
            'summary': {
                'rows': len( self.data ),
                'header_columns': len( self.headers ),
                'observed_columns': width,
                'source_bytes': self.file_size,
                'completeness_percent': completeness,
            },
            'columns': columns,
            'quality': {
                'duplicate_rows': len( duplicates ),
                'empty_rows': len( empty ),
                'ragged_rows': len( ragged ),
                'duplicate_record_examples': duplicates[:20],
                'empty_record_examples': empty[:20],
                'ragged_record_examples': ragged[:20],
                'blank_headers': blanks,
                'duplicate_headers': [ name for name, count in names.items( ) if count > 1 ],
                'whitespace_cells': spaced,
                'formula_like_cells': formula_cells,
            },
            'warnings': list( self.warnings ),
            'cleaning': dict( self.last_clean ),
        }
        self.stats = report

        return report

    # The formula check is conservative and does not evaluate cell contents.
    def IsFormula( self, value ):
        text = value.lstrip( )

        return bool( text and text[0] in '=+-@' ) or value.startswith( ( '\t', '\r', '\n' ) )

    def Analyze( self ):
        report = self.GetReport( )
        print( Render( report ) )

        return report

    def GenReport( self ):
        return Render( self.GetReport( ) )

    def _GetSize( self ):
        size = float( self.file_size )

        for unit in ( 'B', 'KB', 'MB', 'GB' ):
            if size < 1024:
                return f'{size:.1f} {unit}'

            size /= 1024

        return f'{size:.1f} TB'

    # Transform first, then drop empties/duplicates; previews use exactly the same pipeline.
    def PlanClean( self, options ):
        if not self.loaded:
            raise ValueError( 'Load a CSV file first' )

        if not isinstance( options, dict ) or set( options ) - CLEAN_FLAGS:
            raise ValueError( 'Unknown cleaning option' )

        if any( type( value ) is not bool for value in options.values( ) ):
            raise ValueError( 'Cleaning options must be booleans' )

        rows = []
        seen = set( )
        changed = 0
        empty_removed = 0
        duplicate_removed = 0

        for row in self.data:
            cleaned = []

            for cell in row:
                value = cell.strip( ) if options.get( 'trim_whitespace' ) else cell

                if options.get( 'remove_special_chars' ):
                    value = ''.join(
                        char for char in value
                        if char.isalnum( ) or char.isspace( ) or char in '.,;:-'
                    )

                changed += value != cell
                cleaned.append( value )

            if options.get( 'remove_empty_rows' ) and not any( cell.strip( ) for cell in cleaned ):
                empty_removed += 1
                continue

            key = tuple( cleaned )

            if options.get( 'remove_duplicates' ) and key in seen:
                duplicate_removed += 1
                continue

            seen.add( key )
            rows.append( cleaned )

        summary = {
            'rows_before': len( self.data ),
            'rows_after': len( rows ),
            'cells_changed': changed,
            'empty_rows_removed': empty_removed,
            'duplicate_rows_removed': duplicate_removed,
            'options': dict( options ),
        }

        return rows, summary

    def Clean( self, options, *, dry_run=False ):
        try:
            rows, summary = self.PlanClean( options )

            if not dry_run:
                self.data = rows
                self.stats = {}
                self.last_clean = summary

            self.error = ''

            return True
        except ValueError as exc:
            self.error = str( exc )

            return False

    # Export preserves ragged rows and strings; spreadsheet hardening is explicit and opt-in.
    def Export( self, out_file, *, delimiter=None, safe_excel=False ):
        try:
            if not self.loaded:
                raise ValueError( 'Load a CSV file first' )

            separator = self.delimiter if delimiter is None else GetDelimiter( delimiter )
            buffer = io.StringIO( newline='' )
            writer = csv.writer( buffer, delimiter=separator, lineterminator='\r\n' )

            for row in [ self.headers, *self.data ]:
                if safe_excel:
                    row = [ "'" + value if self.IsFormula( value ) else value for value in row ]

                writer.writerow( row )

            WriteNew( out_file, buffer.getvalue( ) )
            self.error = ''

            return True
        except ( OSError, ValueError, UnicodeError, csv.Error ) as exc:
            self.error = f'Could not export: {exc}'

            return False


def Render( report ):
    if 'error' in report:
        return report['error']

    summary = report['summary']
    quality = report['quality']
    completeness = summary['completeness_percent']
    completeness_text = 'N/A (no data cells)' if completeness is None else f'{completeness}%'

    lines = [
        'CSV ANALYSIS',
        f"File: {report['file']}",
        '',
        'SUMMARY',
        f"Rows: {summary['rows']} | Headers: {summary['header_columns']} | "
        f"Observed columns: {summary['observed_columns']}",
        f'Nonblank cell completeness: {completeness_text}',
        '',
        'COLUMNS',
    ]

    for column in report['columns']:
        lines.append(
            f"{column['index']}. {column['name']!r}: {column['type']}; "
            f"blank {column['empty']}; unique {column['unique']}; samples {column['samples']!r}"
        )

        if 'numeric' in column:
            lines.append( f"   Numeric summary: {column['numeric']}" )

    lines.extend( [ '', 'QUALITY' ] )

    for name, value in quality.items( ):
        lines.append( f'{name.replace( "_", " " ).title( )}: {value}' )

    if report['cleaning']:
        lines.extend( [ '', 'CLEANING', json.dumps( report['cleaning'], indent=2 ) ] )

    if 'preview' in report:
        lines.extend( [ '', 'CLEANING PREVIEW (no data changed)', json.dumps(
            report['preview'],
            indent=2,
        ) ] )

    if 'report_error' in report:
        lines.append( f"Report could not be saved: {report['report_error']}" )

    if 'output' in report:
        lines.append( f"Saved data: {report['output']}" )

    lines.extend( report['warnings'] )

    return '\n'.join( lines )


def ShowBanner( ):
    print( 'CSV Analyzer and Cleaner' )


def ShowHelp( ):
    print(
        'load <path> [--delimiter tab] [--encoding utf-8-sig]\n'
        'analyze | report [path.json]\n'
        'clean [--trim] [--drop-empty] [--dedupe] [--remove-special] [--dry-run]\n'
        'export <path> [--delimiter ,] [--safe-excel]\n'
        'help | quit\n\n'
        'Example: load "csv_main/sample_data.csv"\n'
        'Example: clean --trim --drop-empty --dedupe --dry-run\n'
        'Example: export cleaned.csv'
    )


# Preserve the original interactive cleaning selection, with destructive changes explicit.
def GetOptions( ):
    prompts = {
        'remove_empty_rows': 'Remove completely empty rows?',
        'trim_whitespace': 'Trim surrounding whitespace?',
        'remove_special_chars': 'Remove special characters (changes emails and other data)?',
        'remove_duplicates': 'Remove exact duplicate rows?',
    }
    options = {}

    for name, prompt in prompts.items( ):
        options[name] = input( prompt + ' [y/N]: ' ).strip( ).lower( ) in ( 'y', 'yes' )

    return options


def AddCleanArgs( parser ):
    parser.add_argument( '--trim', action='store_true' )
    parser.add_argument( '--drop-empty', action='store_true' )
    parser.add_argument( '--dedupe', action='store_true' )
    parser.add_argument( '--remove-special', action='store_true' )
    parser.add_argument( '--dry-run', action='store_true' )


def CleanOptions( opts ):
    return {
        'trim_whitespace': opts.trim,
        'remove_empty_rows': opts.drop_empty,
        'remove_duplicates': opts.dedupe,
        'remove_special_chars': opts.remove_special,
    }


def BuildParser( ):
    parser = argparse.ArgumentParser(
        description='Analyze and explicitly clean CSV/TSV text without overwriting source files.',
        epilog='Example: python csv_main/csv_analyzer.py analyze csv_main/sample_data.csv --json',
    )
    commands = parser.add_subparsers( dest='command', required=True )

    for name in ( 'analyze', 'clean' ):
        cmd = commands.add_parser( name )
        cmd.add_argument( 'path' )
        cmd.add_argument( '--delimiter', help='Single separator character, or tab' )
        cmd.add_argument( '--encoding', default='utf-8-sig' )
        cmd.add_argument( '--json', action='store_true' )
        cmd.add_argument( '--report', type=Path )

        if name == 'clean':
            AddCleanArgs( cmd )
            cmd.add_argument( '--output', type=Path )
            cmd.add_argument( '--safe-excel', action='store_true' )

    commands.add_parser( 'interactive' )

    return parser


# No POSIX backslash escaping: quoted Windows paths must survive unchanged.
def ParseCommand( text ):
    lexer = shlex.shlex( text, posix=True )
    lexer.whitespace_split = True
    lexer.commenters = ''
    lexer.escape = ''

    return list( lexer )


def ShowReport( report, as_json=False ):
    if as_json:
        print( json.dumps( report, indent=2, ensure_ascii=True ) )
        return

    text = Render( report ) if 'summary' in report else json.dumps( report, indent=2 )

    if sys.stdout.isatty( ) and 'NO_COLOR' not in os.environ:
        text = text.replace( 'CSV ANALYSIS', '\033[36mCSV ANALYSIS\033[0m', 1 )

    print( text )


def RunPrompt( ):
    tool = CSVTool( )
    ShowBanner( )
    print( 'Type help for examples or quit to leave.' )

    while True:
        try:
            parts = ParseCommand( input( 'csv-analyzer> ' ) )

            if not parts:
                continue

            command = parts[0].lower( )
            args = parts[1:]

            if command in ( 'quit', 'exit', 'q' ):
                return 0

            if command == 'help':
                ShowHelp( )
                continue

            if command == 'load':
                parser = argparse.ArgumentParser( prog='load' )
                parser.add_argument( 'path' )
                parser.add_argument( '--delimiter' )
                parser.add_argument( '--encoding', default='utf-8-sig' )
                opts = parser.parse_args( args )

                if not tool.Load( opts.path, delimiter=opts.delimiter, encoding=opts.encoding ):
                    print( tool.error )
                else:
                    print( f'Loaded {len( tool.data )} data records.' )
            elif command == 'analyze':
                ShowReport( tool.GetReport( ) )
            elif command == 'report':
                if len( args ) > 1:
                    raise ValueError( 'Usage: report [path.json]' )

                report = tool.GetReport( )

                if 'error' in report:
                    raise ValueError( report['error'] )

                if args:
                    WriteNew( args[0], json.dumps( report, indent=2, ensure_ascii=True ) + '\n' )

                ShowReport( report )
            elif command == 'clean':
                parser = argparse.ArgumentParser( prog='clean' )
                AddCleanArgs( parser )
                opts = parser.parse_args( args )
                options = CleanOptions( opts ) if args else GetOptions( )
                rows, summary = tool.PlanClean( options )
                print( json.dumps( summary, indent=2 ) )

                if not opts.dry_run:
                    tool.Clean( options )
                    print( 'Updated in-memory data. Use export to save a new file.' )
            elif command == 'export':
                parser = argparse.ArgumentParser( prog='export' )
                parser.add_argument( 'path' )
                parser.add_argument( '--delimiter' )
                parser.add_argument( '--safe-excel', action='store_true' )
                opts = parser.parse_args( args )
                saved = tool.Export(
                    opts.path,
                    delimiter=opts.delimiter,
                    safe_excel=opts.safe_excel,
                )
                print( f'Saved {opts.path}' if saved else tool.error )
            else:
                print( f'Unknown command: {command}. Type help for examples.' )
        except SystemExit:
            continue
        except ( EOFError, KeyboardInterrupt ):
            print( '\nSession closed.' )
            return 0
        except ( OSError, ValueError, UnicodeError ) as exc:
            print( f'Error: {exc}. Check the path/options or use help.' )


def Main( args=None ):
    args = list( sys.argv[1:] if args is None else args )

    if not args:
        return RunPrompt( )

    parser = BuildParser( )
    opts = parser.parse_args( args )

    if opts.command == 'interactive':
        return RunPrompt( )

    tool = CSVTool( )

    try:
        if opts.command == 'clean' and not opts.dry_run and opts.output is None:
            raise ValueError( 'Cleaning requires --output PATH or --dry-run' )

        if opts.command == 'clean' and opts.dry_run and opts.output is not None:
            raise ValueError( '--dry-run does not write data; omit --output' )

        if not tool.Load( opts.path, delimiter=opts.delimiter, encoding=opts.encoding ):
            raise ValueError( tool.error )

        if opts.command == 'clean':
            if opts.dry_run:
                rows, preview = tool.PlanClean( CleanOptions( opts ) )
                report = tool.GetReport( )
                report['preview'] = preview
            else:
                tool.Clean( CleanOptions( opts ) )

                if not tool.Export( opts.output, safe_excel=opts.safe_excel ):
                    raise ValueError( tool.error )

                report = tool.GetReport( )
                report['output'] = str( opts.output )
        else:
            report = tool.GetReport( )

        if opts.report:
            try:
                WriteNew( opts.report, json.dumps( report, indent=2, ensure_ascii=True ) + '\n' )
            except ( OSError, ValueError ) as exc:
                report['report_error'] = str( exc )

        ShowReport( report, opts.json )

        return 2 if 'report_error' in report else 0
    except KeyboardInterrupt:
        print( 'Operation cancelled.', file=sys.stderr )
        return 130
    except ( OSError, ValueError, UnicodeError ) as exc:
        ShowReport( { 'error': str( exc ) }, opts.json )

        return 2


# Keep the former import entry point available without changing the implementation name.
main = Main


if __name__ == '__main__':
    sys.exit( Main( ) )
