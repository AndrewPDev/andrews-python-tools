# Digital Conscience

A dependency-free, read-only Python reviewer by Andrew Piggot. It examines Python syntax and reports potential performance problems, correctness issues, security concerns, and maintenance improvements. It never imports or executes the files being reviewed.

Requires **Python 3.10 or newer**. Run commands below from the repository root.

## Quick start

```console
python code_quality/digital_conscience.py scan code_quality/test_sample.py
python code_quality/digital_conscience.py scan ./code_quality --category performance
python code_quality/digital_conscience.py rules
```

The sample intentionally contains findings. The first command exits with status `1` because it includes a high-severity mutable default.

## Interactive review

Run `python code_quality/digital_conscience.py` without arguments, or use the `interactive` command:

```console
python code_quality/digital_conscience.py interactive
```

At `conscience>`, use `scan <path>`, `report`, `export <path>`, `mode mentor`, `mode intern`, `mode coach`, `rules`, `help`, or `quit`. Paths containing spaces may be quoted; Windows backslashes are preserved. The prompt retains only the latest scan. EOF or Ctrl+C closes the session gracefully. Use CLI scan options when you need filters or exclusions.

Text reports contain summary, findings, and error sections. Terminal output uses severity colors; redirected output and exports stay plain. Set `NO_COLOR` to disable terminal colors.

## Scan options

```console
python code_quality/digital_conscience.py scan ./src --category performance --category correctness
python code_quality/digital_conscience.py scan ./src --rule mutable_default --rule bare_except
python code_quality/digital_conscience.py scan ./src --severity medium --fail-on high
python code_quality/digital_conscience.py scan ./src --exclude generated --exclude "*_generated.py"
python code_quality/digital_conscience.py scan ./src --max-line 140 --mode coach
python code_quality/digital_conscience.py scan "./folder with spaces" --format json --output report.json
```

| Option | Behavior |
| --- | --- |
| `--category NAME` | Select a category; repeat to include several. |
| `--rule ID` | Select individual rules; repeat to include several. |
| `--severity low\|medium\|high` | Minimum reported severity; defaults to `low`. |
| `--fail-on none\|low\|medium\|high` | Exit `1` when a reported finding meets this threshold; defaults to `high`. |
| `--exclude GLOB` | Add a case-sensitive basename or root-relative POSIX-path glob; repeatable. |
| `--max-line N` | Positive physical-line length limit; defaults to `120`. |
| `--format text\|json` | Output format; defaults to `text`. |
| `--output PATH` | Write UTF-8 output instead of printing. Existing reports are overwritten; the parent directory must exist. Python source paths, symlinks, hard links, parent traversal (`..`), and the scan target are rejected. Use an explicit absolute path for a report outside the working directory. |
| `--mode mentor\|intern\|coach` | Change text-report phrasing while retaining all evidence and advice. |

Rule, category, and severity filters intersect. Failure thresholds apply to the filtered findings. Scan errors always produce exit `2`, including with `--fail-on none`.

Default excluded directories: `.git`, `.venv`, `venv`, `__pycache__`, `node_modules`, `build`, and `dist`. Directory scans skip symlink entries and consider only `.py` files. Exclusions apply during directory discovery; an explicitly supplied file is scanned directly. `.gitignore` is not automatically loaded. An empty directory reports zero files and exits successfully; check the scan summary when coverage matters.

## Rules

| ID | Category | Severity | Confidence | Checks |
| --- | --- | --- | --- | --- |
| `bare_except` | correctness | high | high | Exception handlers without an exception type. |
| `empty_except` | correctness | medium | high | Pass-only exception handlers. |
| `mutable_default` | correctness | high | high | List, dictionary, or set literal defaults in functions and lambdas. |
| `no_docstring` | documentation | low | high | Public classes, functions, and methods without docstrings, including async functions. Names starting with `_` are excluded. |
| `long_line` | style | low | high | Physical lines longer than the configured limit. |
| `todo_fixme` | maintenance | low | high | Actual comments starting with TODO, FIXME, or HACK. |
| `sql_format` | security | high | medium | Direct f-string, concatenation, `%`, or `.format()` expressions passed as the first argument to `.execute()` or `.executemany()`. |
| `loop_sort` | performance | medium | medium | Calls named `sorted` or `sort` in repeated loop expressions/bodies. |
| `loop_io` | performance | medium | low | Calls named `open`, `read`, `write`, `execute`, or `executemany` inside loops. |
| `loop_membership` | performance | medium | medium | Membership checks against list literals inside loops. |
| `eager_reduce` | performance | low | medium | List comprehensions passed to calls named `sum`, `any`, or `all`. |

Each finding includes file, line, character column, source snippet, rule ID, severity, confidence, explanation, and a conditional recommendation. Lines and columns are one-based. Findings are sorted by source location. Your naming and parenthesis-spacing conventions are not treated as violations.

### Suppress an intentional finding

Place a rule-specific comment on the finding's reported line:

```python
for row in rows:
    ordered = sorted( row )  # dc: ignore[loop_sort] -- each row is different
```

Multiple rule IDs may be comma-separated inside the brackets. Suppressions in strings do not count. For a multiline call, put the comment on the call's first line. Unknown suppression IDs have no effect.

## Reports and exit codes

- `0`: Scan completed and no reported finding meets the failure threshold.
- `1`: Scan completed with findings at or above the failure threshold.
- `2`: Invalid arguments, configuration, input/read/parse failures, or report-write failure.

JSON output is a single document with no banner or progress messages. Schema version `1` contains `target`, UTC `scan_time`, `enabled_rules`, `summary`, `rating`, `findings`, and `errors`. The summary distinguishes discovered files, successfully scanned files, errors, and excluded entries. Excluded directory counts represent directory entries, not every file beneath them. Errors may include discovery failures, so `files_failed` counts errors rather than only discovered source files.

Every scan starts a fresh report. Syntax or read failures remain visible; they are never counted as clean files. A separate `rating` object provides a transparent 0-10 review score. The formula is `max( 0, 10 - weighted_findings / files_scanned )`, rounded to one decimal place, with weights of 2 for high, 0.5 for medium, and 0.1 for low severity. Scores of 8 or above mean "Few findings", 5 or above mean "Review recommended", and lower scores mean "Needs attention". Empty scans, disabled-all-rule scans, and scans with errors have a null score and "Insufficient coverage" label.

This rating measures only the reported findings under the selected rules, filters, and suppressions. It is not a benchmark, security certification, or comparable project-wide metric: filtering findings or adding clean files can raise it. Findings and scan errors remain the primary evidence.

For Python callers:

```python
from code_quality.digital_conscience import ConscienceTool

review = ConscienceTool( categories=[ 'performance' ] )
report = review.Scan( 'src' )
```

`ScanFile()` and `ScanDir()` are convenience aliases for `Scan()`; all return the same schema. `GenReport()` returns the latest report or `None` before a scan. Analysis itself does not print.

## Limits and changes from the old version

This is static analysis, not a benchmark or a complete security audit. Performance recommendations identify candidates for measurement, not proven slowdowns. Calls are recognized syntactically, without resolving aliases, shadowed builtins, object types, or data flow. In particular, SQL assembled in a separate variable is not traced, and membership in a variable cannot be assumed to mean list membership. Review confidence and conditions before changing code. No automatic fixes are applied.

The rewritten version intentionally supports Python only. The former generic regex checks for other languages, Git workflow checks, and accumulated cross-scan state have been removed. Interactive commands and the CLI are both available. The rating now uses the documented per-file formula above. Old dictionary/report shapes and personality-setting APIs have changed.

Runtime profiling, baseline comparisons, configuration files, and language-specific backends are not included in this version. To investigate a candidate bottleneck, profile a representative workload separately before optimizing it.

## Tests

```console
python -B -m unittest discover -s code_quality -p "test_*.py" -v
```

Regression coverage includes documented functions, nested/async methods, multiline handlers, safe parameterized SQL, mutable defaults, loop boundaries, comprehensions, filters, suppressions, encoding, unreadable/invalid files, fresh reports, nonexecution of target code, JSON output, and exit codes.

## Project conventions

The implementation follows `codex-context-reworked.md`: PascalCase functions/classes, snake_case variables, deliberately spaced calls, logical blank lines, and multiline argument lists. Each Python file begins with a triple-double-quoted module header containing Author, Purpose, and Usage. Other explanatory documentation uses `#` comments above definitions, without function/class docstrings, standalone string comments, shebangs, or decorative banners. Required Python special methods and unittest hook aliases retain their framework-defined names.

Run `python code_quality/digital_conscience.py` directly. Implementation, fixtures, and tests remain in `code_quality/`; no root wrapper is needed. Existing scan commands, interactive commands, report fields, and Python APIs are preserved.
