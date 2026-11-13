"""
Author: Andrew Piggot

Purpose: Review Python source without executing it, identifying potential performance,
correctness, security, and maintenance issues with actionable recommendations.

Usage: Run from the project root:
    python code_quality/digital_conscience.py
    python code_quality/digital_conscience.py scan ./src --category performance
    python code_quality/digital_conscience.py scan ./src --format json --output review.json
    python code_quality/digital_conscience.py scan --help

    No arguments opens the interactive prompt. Use scan for a file or directory,
    --category to filter findings, and --format json --output to export a report.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import io
import json
import os
import re
import sys
import tokenize
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


LEVELS = { 'low': 1, 'medium': 2, 'high': 3 }
EXCLUDES = ( '.git', '.venv', 'venv', '__pycache__', 'node_modules', 'build', 'dist' )
MODES = ( 'mentor', 'intern', 'coach' )


# Stable metadata shared by all findings of a rule.
@dataclass( frozen=True )
class Rule:
    category: str
    severity: str
    confidence: str
    message: str
    reason: str
    advice: str


RULES = {
    'bare_except': Rule(
        'correctness',
        'high',
        'high',
        'Bare exception handler',
        'This also catches KeyboardInterrupt and SystemExit.',
        'Catch the specific expected exceptions; let process-control exceptions propagate.',
    ),
    'empty_except': Rule(
        'correctness',
        'medium',
        'high',
        'Exception silently discarded',
        'A pass-only handler can hide failed operations.',
        'Handle, log, or re-raise the error. If ignoring it is intentional, suppress this rule with a reason.',
    ),
    'mutable_default': Rule(
        'correctness',
        'high',
        'high',
        'Mutable default argument',
        'Literal lists, dictionaries, and sets used as defaults are shared across calls.',
        'Use None as the default and create the container inside the function.',
    ),
    'no_docstring': Rule(
        'documentation',
        'low',
        'high',
        'Missing public docstring',
        'Callers lack an explanation of the public interface.',
        'Document purpose, inputs, return values, and relevant exceptions.',
    ),
    'long_line': Rule(
        'style',
        'low',
        'high',
        'Line exceeds the configured limit',
        'Long lines can make review harder.',
        'Split the expression across lines or adjust max_line to match your project.',
    ),
    'todo_fixme': Rule(
        'maintenance',
        'low',
        'high',
        'Outstanding maintenance comment',
        'TODO, FIXME, or HACK marks work that may need follow-up.',
        'Resolve it or link it to a tracked issue; it need not block a commit.',
    ),
    'sql_format': Rule(
        'security',
        'high',
        'medium',
        'Dynamically constructed SQL argument',
        'Interpolated values may become executable SQL when they contain untrusted input.',
        'Bind values using your database driver parameters. Review identifiers separately; '
        'static analysis cannot establish input trust.',
    ),
    'loop_sort': Rule(
        'performance',
        'medium',
        'medium',
        'Sorting within a loop',
        'Sorting on each iteration may repeat avoidable work.',
        'Move sorting outside the loop only if the input and required ordering stay unchanged.',
    ),
    'loop_io': Rule(
        'performance',
        'medium',
        'low',
        'Possible I/O call within a loop',
        'Repeated file or database operations may dominate runtime.',
        'Profile this path; consider a shared file handle or batched queries where ordering, '
        'transactions, and memory allow it.',
    ),
    'loop_membership': Rule(
        'performance',
        'medium',
        'medium',
        'Literal-list membership within a loop',
        'A list membership search examines elements sequentially and may rebuild the list.',
        'For repeated lookups, consider a set created before the loop if values are hashable '
        'and equality semantics allow it.',
    ),
    'eager_reduce': Rule(
        'performance',
        'low',
        'medium',
        'Reduction materializes a list comprehension',
        'The temporary list retains all produced items before reduction.',
        'Consider a generator expression. For any/all this also short-circuits evaluation, '
        'so check side effects and exception timing.',
    ),
}


# A source location and a recommendation independent of presentation.
@dataclass( frozen=True )
class Finding:
    file: str
    line: int
    column: int
    rule: str
    category: str
    severity: str
    confidence: str
    message: str
    reason: str
    advice: str
    code: str


# Inspect Python syntax without importing or executing the target.
class PyReview:
    # Prepare source lines, enabled checks, and comment-based suppressions.
    def __init__( self, file_path, source, enabled, max_line ):
        self.file_path = str( file_path )
        self.lines = source.splitlines( )

        self.enabled = enabled
        self.max_line = max_line

        self.findings = []
        self.loop_depth = 0
        self.ignored = {}
        self.comments = []

        self.handlers = {
            'FunctionDef': self.CheckFunc,
            'AsyncFunctionDef': self.CheckFunc,
            'ClassDef': self.CheckClass,
            'Lambda': self.CheckLambda,
            'ExceptHandler': self.CheckExcept,
            'For': self.CheckFor,
            'AsyncFor': self.CheckFor,
            'While': self.CheckWhile,
            'ListComp': self.CheckComp,
            'SetComp': self.CheckComp,
            'DictComp': self.CheckComp,
            'GeneratorExp': self.CheckComp,
            'Compare': self.CheckCompare,
            'Call': self.CheckCall,
        }

        for token in tokenize.generate_tokens( io.StringIO( source ).readline ):
            if token.type != tokenize.COMMENT:
                continue

            self.comments.append( ( token.start[0], token.string ) )

            match = re.search( r'\bdc:\s*ignore\[([^]]+)\]', token.string )

            if match:
                rule_ids = match.group( 1 ).split( ',' )
                ignored = self.ignored.setdefault( token.start[0], set( ) )

                ignored.update( item.strip( ) for item in rule_ids )

    # Dispatch syntax nodes to PascalCase checks, walking unhandled nodes recursively.
    def Visit( self, node ):
        self.handlers.get( type( node ).__name__, self.Walk )( node )

    # Visit child syntax nodes in source order without executing code.
    def Walk( self, node ):
        for child in ast.iter_child_nodes( node ):
            self.Visit( child )

    # Record an enabled, unsuppressed finding.
    def Add( self, rule_id, node=None, line=None ):
        if line is None:
            line = node.lineno

        if rule_id not in self.enabled or rule_id in self.ignored.get( line, set( ) ):
            return

        rule = RULES[rule_id]
        raw_line = self.lines[line - 1]

        byte_col = getattr( node, 'col_offset', 0 )
        column = len( raw_line.encode( 'utf-8' )[:byte_col].decode( 'utf-8' ) ) + 1
        finding = Finding(
            self.file_path,
            line,
            column,
            rule_id,
            rule.category,
            rule.severity,
            rule.confidence,
            rule.message,
            rule.reason,
            rule.advice,
            raw_line.strip( ),
        )

        self.findings.append( finding )

    # Check physical lines and real comments, excluding strings.
    def CheckText( self ):
        for line_num, line in enumerate( self.lines, 1 ):
            if len( line ) > self.max_line:
                self.Add( 'long_line', line=line_num )

        for line_num, comment in self.comments:
            if re.match( r'#\s*(TODO|FIXME|HACK)\b', comment, re.IGNORECASE ):
                self.Add( 'todo_fixme', line=line_num )

    # Reset loop context for separately executed bodies.
    def CheckScope( self, node ):
        self.Visit( node.args )

        for decorator in getattr( node, 'decorator_list', [] ):
            self.Visit( decorator )

        depth = self.loop_depth
        self.loop_depth = 0

        if isinstance( node.body, list ):
            for stmt in node.body:
                self.Visit( stmt )
        else:
            self.Visit( node.body )

        self.loop_depth = depth

    # Check defaults and public function documentation.
    def CheckFunc( self, node ):
        if not node.name.startswith( '_' ) and ast.get_docstring( node ) is None:
            self.Add( 'no_docstring', node )

        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if isinstance( default, ( ast.List, ast.Dict, ast.Set ) ):
                self.Add( 'mutable_default', default )

        self.CheckScope( node )

    # Check public class documentation.
    def CheckClass( self, node ):
        if not node.name.startswith( '_' ) and ast.get_docstring( node ) is None:
            self.Add( 'no_docstring', node )

        self.Walk( node )

    # Check lambda defaults without inheriting the enclosing loop.
    def CheckLambda( self, node ):
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if isinstance( default, ( ast.List, ast.Dict, ast.Set ) ):
                self.Add( 'mutable_default', default )

        self.CheckScope( node )

    # Inspect real handlers, including multiline ones.
    def CheckExcept( self, node ):
        if node.type is None:
            self.Add( 'bare_except', node )

        if len( node.body ) == 1 and isinstance( node.body[0], ast.Pass ):
            self.Add( 'empty_except', node )

        self.Walk( node )

    # Visit the iterable once, then the repeated body.
    def CheckFor( self, node ):
        self.Visit( node.iter )
        self.Visit( node.target )

        self.loop_depth += 1

        for stmt in node.body:
            self.Visit( stmt )

        self.loop_depth -= 1

        for stmt in node.orelse:
            self.Visit( stmt )

    # While tests are repeated as well as their bodies.
    def CheckWhile( self, node ):
        self.loop_depth += 1

        self.Visit( node.test )

        for stmt in node.body:
            self.Visit( stmt )

        self.loop_depth -= 1

        for stmt in node.orelse:
            self.Visit( stmt )

    # Track repeated expressions inside comprehensions.
    def CheckComp( self, node ):
        depth = self.loop_depth

        for gen in node.generators:
            self.Visit( gen.iter )

            self.loop_depth += 1

            self.Visit( gen.target )

            for cond in gen.ifs:
                self.Visit( cond )

        if isinstance( node, ast.DictComp ):
            self.Visit( node.key )
            self.Visit( node.value )
        else:
            self.Visit( node.elt )

        self.loop_depth = depth

    # Flag repeated membership only when a list is syntactically known.
    def CheckCompare( self, node ):
        if self.loop_depth:
            for op, rhs in zip( node.ops, node.comparators ):
                if isinstance( op, ( ast.In, ast.NotIn ) ) and isinstance( rhs, ast.List ):
                    self.Add( 'loop_membership', node )
                    break

        self.Walk( node )

    # Inspect candidate performance problems and SQL construction.
    def CheckCall( self, node ):
        call_name = node.func.id if isinstance( node.func, ast.Name ) else getattr( node.func, 'attr', '' )

        if self.loop_depth:
            if call_name in ( 'sorted', 'sort' ):
                self.Add( 'loop_sort', node )

            if call_name in ( 'open', 'execute', 'executemany', 'read', 'write' ):
                self.Add( 'loop_io', node )

        if isinstance( node.func, ast.Name ) and call_name in ( 'sum', 'any', 'all' ):
            if node.args and isinstance( node.args[0], ast.ListComp ):
                self.Add( 'eager_reduce', node )

        if isinstance( node.func, ast.Attribute ) and call_name in ( 'execute', 'executemany' ) and node.args:
            query = node.args[0]
            dynamic = isinstance( query, ast.JoinedStr ) and any(
                isinstance( item, ast.FormattedValue ) for item in query.values
            )
            dynamic = dynamic or (
                isinstance( query, ast.BinOp )
                and isinstance( query.op, ( ast.Mod, ast.Add ) )
            )
            dynamic = dynamic or (
                isinstance( query, ast.Call )
                and isinstance( query.func, ast.Attribute )
                and query.func.attr == 'format'
            )

            if dynamic:
                self.Add( 'sql_format', node )

        self.Walk( node )


# Discover files and collect isolated, serializable scan reports.
class ConscienceTool:
    # Validate scan settings and prepare an independent reviewer with selected rules.
    def __init__( self, *, rules=None, categories=None, severity='low', exclude=( ), max_line=120 ):
        if severity not in LEVELS:
            raise ValueError( f'Unknown severity: { severity }' )

        if max_line < 1:
            raise ValueError( 'max_line must be positive' )

        enabled = set( RULES if rules is None else rules )

        if enabled - RULES.keys( ):
            raise ValueError( f'Unknown rules: { ", ".join( sorted( enabled - RULES.keys( ) ) ) }' )

        known_cats = { rule.category for rule in RULES.values( ) }

        if categories is not None and set( categories ) - known_cats:
            raise ValueError( 'Unknown category' )

        self.enabled = { key for key in enabled if LEVELS[RULES[key].severity] >= LEVELS[severity]
            and ( categories is None or RULES[key].category in categories ) }
        self.exclude = ( *EXCLUDES, *exclude )
        self.max_line = max_line
        self.report = None

    # Match case-sensitive globs against basenames and root-relative paths.
    def IsExcluded( self, path, root ):
        rel_path = path.relative_to( root ).as_posix( )

        return any( fnmatch.fnmatchcase( path.name, pattern ) or fnmatch.fnmatchcase( rel_path, pattern )
            for pattern in self.exclude )

    # Start a new report; retain failures instead of treating them as clean files.
    def Scan( self, target ):
        target = Path( target ).absolute( )
        findings, errors, files = [], [], []
        skipped = 0

        # Record a discovery, read, or parsing failure against its source path.
        def AddError( path, exc ):
            errors.append( { 'file': str( path ), 'message': str( exc ) } )

        if target.is_file( ):
            if target.suffix != '.py':
                AddError( target, 'Only Python (.py) files are supported' )
            else:
                files.append( target )
        elif target.is_dir( ):
            # Preserve directory traversal failures in the current report.
            def WalkError( exc ):
                AddError( exc.filename or target, exc )

            for root, dirs, names in os.walk( target, onerror=WalkError, followlinks=False ):
                root = Path( root )
                kept = []

                for name in sorted( dirs ):
                    path = root / name

                    if path.is_symlink( ) or self.IsExcluded( path, target ):
                        skipped += 1
                    else:
                        kept.append( name )

                dirs[:] = kept

                for name in sorted( names ):
                    path = root / name

                    if path.suffix != '.py':
                        continue

                    if path.is_symlink( ) or self.IsExcluded( path, target ):
                        skipped += 1
                    else:
                        files.append( path )
        else:
            AddError( target, 'Path does not exist or is not a regular file/directory' )

        scanned = 0

        for path in sorted( files ):
            try:
                with tokenize.open( path ) as handle:
                    source = handle.read( )

                tree = ast.parse( source, filename=str( path ) )
                review = PyReview( path, source, self.enabled, self.max_line )

                review.CheckText( )
                review.Visit( tree )
                findings.extend( review.findings )

                scanned += 1
            except (
                OSError,
                UnicodeError,
                SyntaxError,
                tokenize.TokenError,
                LookupError,
                ValueError,
                RecursionError,
            ) as exc:
                AddError( path, exc )

        findings.sort( key=lambda item: ( item.file, item.line, item.column, item.rule ) )

        self.report = {
            'schema_version': 1,
            'target': str( target ),
            'scan_time': datetime.now( timezone.utc ).isoformat( ),
            'summary': {
                'files_found': len( files ),
                'files_scanned': scanned,
                'files_failed': len( errors ),
                'entries_skipped': skipped,
                'total_issues': len( findings ),
                'severity_breakdown': {
                    level: sum( item.severity == level for item in findings )
                    for level in LEVELS
                },
            },
            'enabled_rules': sorted( self.enabled ),
            'findings': [asdict( item ) for item in findings],
            'errors': errors,
        }
        self.report['rating'] = Rate( self.report )

        return self.report

    # Scan a file using the same report schema as directory scans.
    def ScanFile( self, file_path ):
        return self.Scan( file_path )

    # Scan a directory with a fresh report.
    def ScanDir( self, directory ):
        return self.Scan( directory )

    # Return the latest report, if a scan has run.
    def GenReport( self ):
        return self.report


# Scores apply only to the active rules and successfully scanned source files.
# Return a transparent 0-10 heuristic rating; incomplete or empty scans are unrated.
def Rate( report ):
    count = report['summary']['files_scanned']

    if report['errors'] or not count or not report['enabled_rules']:
        return { 'score': None, 'label': 'Insufficient coverage', 'penalty_per_file': None }

    weights = { 'high': 2.0, 'medium': 0.5, 'low': 0.1 }
    penalty = sum( weights[item['severity']] for item in report['findings'] ) / count
    score = round( max( 0.0, 10.0 - penalty ), 1 )
    label = 'Few findings' if score >= 8 else 'Review recommended' if score >= 5 else 'Needs attention'

    return { 'score': score, 'label': label, 'penalty_per_file': round( penalty, 3 ) }


# Explicit output paths may be outside the project, but cannot replace source files.
# Resolve report paths and reject source suffixes, source aliases, and scan-target overwrites.
def CheckOutput( dest, target ):
    dest = Path( dest )
    target = Path( target ).resolve( )
    resolved = dest.resolve( )

    if '..' in dest.parts:
        raise ValueError( 'Use an explicit output path without parent traversal (..)' )

    if dest.is_symlink( ) or resolved.suffix.lower( ) in ( '.py', '.pyw', '.pyi' ) or resolved == target:
        raise ValueError( 'Output must be a report path, not a symlink, scan target, or Python source file' )

    if dest.exists( ) and dest.stat( ).st_nlink > 1:
        raise ValueError( 'Output cannot be a hard-linked file' )


# Color report headings and severity lines only in terminals unless NO_COLOR is set.
def ColorText( text ):
    if not sys.stdout.isatty( ) or 'NO_COLOR' in os.environ:
        return text

    lines = []

    for line in text.splitlines( ):
        color = None

        if '[high/' in line or line.startswith( 'ERROR ' ):
            color = '31'
        elif '[medium/' in line:
            color = '33'
        elif '[low/' in line:
            color = '36'
        elif line in ( 'DIGITAL CONSCIENCE', 'SUMMARY', 'FINDINGS', 'SCAN ERRORS' ):
            color = '1;36'

        lines.append( f'\033[{ color }m{ line }\033[0m' if color else line )

    return '\n'.join( lines )


# Run review commands until quit, EOF, or interruption; keep only the latest scan for export.
def RunPrompt( ):
    checker = ConscienceTool( )
    mode = 'mentor'

    print( 'Digital Conscience is ready. Type help for examples or quit to leave.' )

    while True:
        try:
            entry = input( 'conscience> ' ).strip( )

            if not entry:
                continue

            parts = entry.split( maxsplit=1 )
            cmd = parts[0].lower( )
            arg = parts[1].strip( ) if len( parts ) > 1 else ''

            if len( arg ) >= 2 and arg[0] == arg[-1] and arg[0] in ( "'", '"' ):
                arg = arg[1:-1]

            if cmd in ( 'quit', 'exit', 'q' ):
                return 0

            if cmd == 'help':
                print( 'scan <path>     Review a Python file or folder\n'
                    'report          Show the latest report\n'
                    'export <path>   Export the latest report as JSON\n'
                    'mode <name>     Choose mentor, intern, or coach\n'
                    'rules           List available checks\n'
                    'quit            Exit\n\n'
                    'Examples: scan ./src | scan "C:\\My Project" | export review.json\n'
                    'Use the scan CLI with --help for filters and exclusions.' )
            elif cmd in ( 'scan', 'scandir' ):
                if not arg:
                    raise ValueError( 'Provide a file or folder, for example: scan ./src' )

                print( ColorText( Render( checker.Scan( arg ), mode ) ) )
            elif cmd == 'mode':
                if arg not in MODES:
                    raise ValueError( 'Choose mentor, intern, or coach' )

                mode = arg

                print( f'Feedback mode is now { mode }.' )
            elif cmd == 'rules':
                Main( ['rules'] )
            elif cmd in ( 'report', 'export' ):
                report = checker.GenReport( )

                if report is None:
                    raise ValueError( 'Run scan <path> first' )

                if cmd == 'report':
                    print( ColorText( Render( report, mode ) ) )
                else:
                    if not arg:
                        raise ValueError( 'Provide a report path, for example: export review.json' )

                    CheckOutput( arg, report['target'] )
                    Path( arg ).write_text( json.dumps( report, indent=2 ) + '\n', encoding='utf-8' )
                    print( f'Report saved to { arg }.' )
            else:
                print( f'Unknown command: { cmd }. Type help to see examples.' )
        except ( EOFError, KeyboardInterrupt ):
            print( '\nReview session closed.' )

            return 0
        except ( OSError, ValueError ) as exc:
            print( f'Could not complete that command: { exc }. Check the path or type help.' )


# Render all evidence and advice regardless of the selected tone.
def Render( report, mode='mentor' ):
    prefixes = {
        'mentor': 'Recommendation',
        'intern': 'Future you would appreciate this',
        'coach': 'Next improvement',
    }
    summary = report['summary']
    rating = report['rating']
    score = 'Unavailable' if rating['score'] is None else f"{ rating['score'] }/10"
    lines = [
        'DIGITAL CONSCIENCE',
        '',
        'SUMMARY',
        f"Review score: { score } ({ rating['label'] })",
        'Rule-based guidance for this scan; not a runtime benchmark.',
        f"Scanned { summary['files_scanned'] }/{ summary['files_found'] } Python files; "
        f"{ summary['total_issues'] } findings; { summary['files_failed'] } errors; "
        f"{ summary['entries_skipped'] } excluded entries.",
    ]

    lines.extend( ['', 'FINDINGS'] )

    if not report['findings']:
        lines.append( 'No findings from the selected rules.' )

    for item in report['findings']:
        lines.extend(
            [
                '',
                f"{ item['file'] }:{ item['line'] }:{ item['column'] } "
                f"[{ item['severity'] }/{ item['confidence'] } confidence] { item['rule'] }: { item['message'] }",
                f"  Code: { item['code'] }",
                f"  Why: { item['reason'] }",
                f"  { prefixes[mode] }: { item['advice'] }",
            ],
        )

    lines.extend( ['', 'SCAN ERRORS'] )

    if not report['errors']:
        lines.append( 'None.' )

    for error in report['errors']:
        lines.append( f"ERROR { error['file'] }: { error['message'] }" )

    return '\n'.join( lines )


# Errors take precedence over configured finding thresholds.
def ExitCode( report, fail_on ):
    if report['errors']:
        return 2

    if fail_on != 'none' and any( LEVELS[item['severity']] >= LEVELS[fail_on] for item in report['findings'] ):
        return 1

    return 0


# Build the automation-friendly command interface.
def BuildParser( ):
    parser = argparse.ArgumentParser(
        description='Read-only Python review with actionable recommendations.',
        epilog='Examples: code_quality/digital_conscience.py scan ./src --category performance; '
        'code_quality/digital_conscience.py interactive',
    )
    commands = parser.add_subparsers( dest='command', required=True )
    scan = commands.add_parser( 'scan', help='Review a Python file or directory without running it' )

    scan.add_argument( 'path' )
    scan.add_argument(
        '--category',
        action='append',
        choices=sorted( { item.category for item in RULES.values( ) } ),
    )
    scan.add_argument( '--rule', action='append', choices=sorted( RULES ) )
    scan.add_argument( '--severity', choices=LEVELS, default='low', help='Minimum severity to report' )
    scan.add_argument(
        '--exclude',
        action='append',
        default=[],
        help='Additional basename or relative-path glob; repeatable',
    )
    scan.add_argument( '--max-line', type=int, default=120 )
    scan.add_argument( '--format', choices=( 'text', 'json' ), default='text' )
    scan.add_argument( '--output', type=Path, help='Write the report to a file instead of stdout' )
    scan.add_argument( '--mode', choices=MODES, default='mentor' )
    scan.add_argument( '--fail-on', choices=( 'none', *LEVELS ), default='high' )
    commands.add_parser( 'interactive', help='Open the interactive review prompt' )
    commands.add_parser( 'rules', help='List available rules and recommendations' )

    return parser


# Run the CLI and return a meaningful process status.
def Main( args=None ):
    parser = BuildParser( )
    args = list( sys.argv[1:] if args is None else args )
    opts = parser.parse_args( args or ['interactive'] )

    if opts.command == 'interactive':
        return RunPrompt( )

    if opts.command == 'rules':
        for rule_id, rule in sorted( RULES.items( ) ):
            print(
                f'{ rule_id } [{ rule.category }/{ rule.severity }/{ rule.confidence }]: '
                f'{ rule.message }\n  { rule.advice }'
            )

        return 0

    try:
        checker = ConscienceTool(
            rules=opts.rule,
            categories=opts.category,
            severity=opts.severity,
            exclude=opts.exclude,
            max_line=opts.max_line,
        )

        if opts.output:
            CheckOutput( opts.output, opts.path )

        report = checker.Scan( opts.path )
        if opts.format == 'json':
            rendered = json.dumps( report, indent=2, ensure_ascii=True )
        else:
            rendered = Render( report, opts.mode )

        if opts.output:
            opts.output.write_text( rendered + '\n', encoding='utf-8' )
        else:
            print( ColorText( rendered ) if opts.format == 'text' else rendered )

        return ExitCode( report, opts.fail_on )
    except KeyboardInterrupt:
        print( '\nReview cancelled.', file=sys.stderr )

        return 130
    except ( OSError, ValueError ) as exc:
        print(
            f'Error: { exc }. Check the path, permissions, and options; use --help for examples.',
            file=sys.stderr,
        )

        return 2


if __name__ == '__main__':
    sys.exit( Main( ) )
