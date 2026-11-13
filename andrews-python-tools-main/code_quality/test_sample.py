"""
Author: Andrew Piggot

Purpose: Provide intentional code-quality findings for a read-only scanner demonstration,
including a mutable default, repeated sorting, and unnecessary list materialization.

Usage: Scan this fixture from the project root:
    python code_quality/digital_conscience.py scan code_quality/test_sample.py
    python code_quality/digital_conscience.py scan code_quality/test_sample.py --category performance

    The first command intentionally exits with status 1 because of high-severity findings.
    This file is sample input, not an application to execute directly.
"""

def ReviewRows( rows, saved=[] ):
    for row in rows:
        ordered = sorted( rows )

        if row in [1, 2, 3]:
            saved.append( ordered )

    return sum( [len( item ) for item in saved] )
