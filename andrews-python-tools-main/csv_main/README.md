# CSV Analyzer and Cleaner

A dependency-free Python 3.10+ tool for inspecting and explicitly cleaning CSV/TSV text. Run `csv_main/csv_analyzer.py` directly from the project root. **Excel workbooks (`.xlsx`, `.xls`, `.xlsm`) are not supported**; export them to CSV first. The old CSV/Excel label overstated the implementation's capabilities.

## Quick start

```console
python csv_main/csv_analyzer.py
python csv_main/csv_analyzer.py analyze csv_main/sample_data.csv
python csv_main/csv_analyzer.py analyze csv_main/sample_data.csv --json
python csv_main/csv_analyzer.py analyze csv_main/sample_data.csv --report analysis.json
python csv_main/csv_analyzer.py clean csv_main/sample_data.csv --trim --drop-empty --dedupe --dry-run
python csv_main/csv_analyzer.py clean csv_main/sample_data.csv --trim --drop-empty --dedupe --output cleaned.csv
```

No arguments starts the interactive prompt. Use `--help` or `<command> --help` for CLI options. No dependencies or root-level wrapper scripts are needed.

## Loading and analysis

The first CSV record is always the header. Header-only files and single-column CSVs are supported; completely empty files and malformed quoted records return errors. UTF-8 with or without a BOM is the default. Comma, semicolon, tab, and pipe delimiters are detected heuristically. Uncertain detection generates a report warning; specify the delimiter when necessary.

```console
python csv_main/csv_analyzer.py analyze data.tsv --delimiter tab
python csv_main/csv_analyzer.py analyze legacy.csv --delimiter ";" --encoding cp1252
```

Files load transactionally: a failed load leaves the previous interactive dataset intact and reports the error. There is no silent encoding replacement. Quoted commas and embedded newlines are preserved.

Reports include:

- Row counts, header width, observed width, original file size, and nonblank-cell completeness.
- Per-column blank/missing counts, distinct values, deterministic first-seen samples, and inferred types.
- Decimal minimum, maximum, and mean for columns that are entirely numeric after ignoring blanks. Numeric statistics are JSON strings to avoid binary floating-point conversion; means use 128-digit decimal precision.
- Exact duplicate rows, empty rows, mismatched row widths, blank/duplicate headers, surrounding whitespace, and formula-like cells.
- Up to 20 logical record numbers for duplicate/empty/ragged examples. Record 1 is the header; embedded newlines mean record numbers are not necessarily physical line numbers.

Duplicate detection uses whole tuples, so `"a,b",c` and `a,"b,c"` remain distinct. Extra fields appear as indexed extra columns rather than disappearing. Duplicate header names remain separate indexed columns. Analysis never changes source values.

Type inference is deliberately conservative: every nonblank value must match the inferred type. Leading-zero identifiers, locale-specific numbers such as `1,23`, `NaN`, infinities, mixed columns, and ambiguous slash dates stay text. ISO dates and timestamps are recognized without converting the data. Numeric literals are limited to 100 characters with at most three exponent digits for inference.

Completeness is the percentage of nonblank cells in the observed rectangular width, including missing cells in short rows. It is `null` when there are no data cells. It is not a general quality score or a guarantee of correct data.

## Cleaning

No cleaning operation is enabled implicitly. Choose any combination:

| Flag | Behavior |
| --- | --- |
| `--trim` | Strip surrounding whitespace from data cells. |
| `--drop-empty` | Remove records whose cells are all blank after selected transformations. |
| `--dedupe` | Keep the first exact duplicate after selected transformations. |
| `--remove-special` | Destructively remove characters except Unicode alphanumerics, whitespace, and `.,;:-`. This can alter emails, identifiers, and formulas; use only deliberately. |
| `--dry-run` | Report proposed counts without changing or exporting data. |
| `--output PATH` | Save the cleaned dataset to a new CSV file; required unless using `--dry-run`. |
| `--safe-excel` | Prefix formula-like exported fields with an apostrophe, including headers; does not alter in-memory data. |

The same cleaning pipeline powers previews and applied changes: transform cells, remove empty rows, then deduplicate. Reports count changed cells even in rows later removed. Headers and ragged widths are never silently renamed, padded, or truncated. With no cleaning flags, export copies the parsed values without cleaning.

`--safe-excel` is optional because it changes exported values, including negative numbers beginning with `-`. It conservatively detects leading `=`, `+`, `-`, `@`, tabs, and newlines after whitespace handling. It is a mitigation for spreadsheet interpretation, not a guarantee across all spreadsheet applications. The analyzer never executes formulas.

## Export and reports

Exports use UTF-8, CRLF record separators, the loaded delimiter, and standard CSV quoting. Parsed values are preserved unless a cleaning/safe-export option changes them; the original quoting, BOM, and record formatting are not reproduced byte-for-byte. Quoted embedded line endings remain cell contents.

Outputs and reports use exclusive creation and never overwrite existing files or destination symlinks. Parent directories must exist. Output paths containing `..` are rejected; explicit absolute destinations are allowed. Inputs and relative paths resolve from the current working directory. Original source files are never modified by analysis or cleaning. Disk-write failure can leave a partial newly created output; choose another name or remove that partial file before retrying.

`--report PATH` writes a JSON report. `--json` prints one JSON document without banners or progress messages. Report-write failures appear in `report_error` and produce exit code 2; any completed CSV export remains saved. Reports include sample cell values and filenames, so treat them as potentially sensitive.

Exit codes: `0` for completed operations (including detected data-quality issues), `2` for invalid input/options or load/export/report errors, and `130` for interrupted CLI work. Interactive EOF/Ctrl+C exits cleanly. Terminal headings use color when available; `NO_COLOR` disables it and redirected output stays plain.

## Interactive commands

```text
load "csv_main/sample_data.csv"
analyze
clean --trim --drop-empty --dedupe --dry-run
clean --trim --drop-empty --dedupe
export cleaned.csv
report analysis.json
quit
```

`load` accepts `--delimiter` and `--encoding`. `clean` without flags prompts for the original four cleaning options. `export` accepts `--delimiter` and `--safe-excel`. `report` without a path displays the current report. Quoted Windows paths retain their backslashes. Run `help` for examples.

## Python API and compatibility

`CSVTool`, `Load`, `Analyze`, `Clean`, `Export`, `GenReport`, `ShowBanner`, `ShowHelp`, and `GetOptions` remain available. `Main` has a compatibility alias named `main`.

- `Load`, `Clean`, and `Export` still return booleans; read `tool.error` on failure. They no longer print operation messages.
- `GetReport()` returns structured data. `Analyze()` prints and returns it; `GenReport()` returns formatted text.
- `PlanClean( options )` returns proposed rows and a summary without mutation. `Clean( options, dry_run=True )` validates/previews without committing changes.
- The existing option keys remain `trim_whitespace`, `remove_empty_rows`, `remove_duplicates`, and `remove_special_chars`. Unknown or nonboolean options are rejected.
- `stats` reflects the latest report and is invalidated on successful load/clean. File size refers to the originally loaded bytes, not an estimated cleaned size.

## Limits and tests

This is an in-memory tool, not a streaming engine. Limits are 32 MiB of source bytes, 250,000 data records, and 2,000,000 actual or rectangular cells. The standard library CSV field-size limit also applies. Sparse, extremely wide ragged datasets are rejected before rectangular analysis can become excessive. Very large data should use a dedicated data-processing tool.

The included `sample_data.csv` has synthetic data, a duplicate record, blank cells, and an empty record. Its stray unmatched quote was repaired so strict parsing can load it. Expected baseline: 12 data records, 6 columns, 1 duplicate, 1 empty row; trimming/dropping empties/deduplicating leaves 10 records.

```console
python -B -m unittest discover -s csv_main -p "test_*.py" -v
```

Tests cover quoted/multiline records, encodings, delimiter selection, single-column/header-only files, transactional failures, tuple-based duplicates, ragged records, numeric/date inference, preview parity, explicit cleaning, overwrite protection, safe spreadsheet exports, resource bounds, and CLI/interactive behavior.
