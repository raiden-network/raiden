#!/usr/bin/env python3
""" Utility to compare to report the number of increased errors in the same
code.

The exit code of the tool will be 0 if the number of reported errors stayed the
same *or decreased*. Otherwise it will be number of additional errors reported.

This utility assumes both reports are produced by the *same version of Mypy*,
and that *the generated report has stable messages*, otherwise the errors
results are not stable.
"""
import re
import sys
from collections import defaultdict
from itertools import groupby
from typing import Dict, Iterator, NamedTuple, Optional, Tuple

MYPY_LINE = re.compile(
    r"^"
    r"(?P<filename>([^:]|\\:)+):"
    r"((?P<linenum>([0-9]+)):)?"
    r"(?P<level>([^:]|\\:)+):"
    r"(?P<message>.+$)"
)


class FileErrorType(NamedTuple):
    filename: str
    errortype: str


class Error(NamedTuple):
    filename: str
    linenum: str
    level: str
    message: str


NewErrorCountPerFile = Dict[FileErrorType, int]
UNKNOWN_REPORT_LINE = "Unrecognized line format"


def compare_errors(error_old: Error, error_new: Error) -> int:
    # Errors for `filename` have been fixed according to the new report.
    if error_old.filename < error_new.filename:
        return -1

    # Assuming stable output.
    message_old = (error_old.level, error_old.message)
    message_new = (error_new.level, error_new.message)

    # The error `(level, message)` is fixed according to the new report
    if message_old < message_new:
        return -1

    if message_old == message_new:
        return 0

    # Do not compare line numbers. If the error moved around it does not
    # matter, only new and fixed bugs.

    return 1


def next_error(f: Iterator[Error]) -> Optional[Error]:
    try:
        return next(f)
    except StopIteration:
        return None


def get_errors(previous_report: str) -> Iterator[Error]:
    with open(previous_report, "r") as file:
        for line in file:
            match = MYPY_LINE.match(line)
            assert match, UNKNOWN_REPORT_LINE

            error = Error(
                filename=match["filename"],
                linenum=match["linenum"],
                level=match["level"],
                message=match["message"],
            )
            yield error


def sort_by_filename_level_error(error: Error) -> Tuple:
    return error.filename, error.level, error.message


def compare_reports(previous_report: str, new_report: str) -> Tuple[NewErrorCountPerFile, int]:
    previous_errors_unsorted = get_errors(previous_report)
    new_errors_unsorted = get_errors(new_report)

    previous_errors = sorted(previous_errors_unsorted, key=sort_by_filename_level_error)
    new_errors = sorted(new_errors_unsorted, key=sort_by_filename_level_error)

    previous_errors_it = iter(previous_errors)
    new_errors_it = iter(new_errors)

    new_errors_count = 0
    error_count: NewErrorCountPerFile = defaultdict(int)

    previous_error = next_error(previous_errors_it)
    new_error = next_error(new_errors_it)

    while previous_error is not None and new_error is not None:
        compare = compare_errors(previous_error, new_error)

        # The new report has a new error
        if compare > 0:
            new_errors_count += 1
            error_count[FileErrorType(new_error.filename, new_error.message)] += 1

        if compare < 0:
            previous_error = next_error(previous_errors_it)
        elif compare == 0:
            previous_error = next_error(previous_errors_it)
            new_error = next_error(new_errors_it)
        else:
            new_error = next_error(new_errors_it)

    # Extra lines in the new report are new errors
    while new_error is not None:
        new_errors_count += 1
        error_count[FileErrorType(new_error.filename, new_error.message)] += 1

        new_error = next_error(new_errors_it)

    return error_count, new_errors_count


def print_changes(report: NewErrorCountPerFile) -> None:
    error_types_grouped_by_filename = groupby(sorted(report), key=lambda k: k.filename)

    for filename, error_types_it in error_types_grouped_by_filename:
        error_types = list(error_types_it)
        total_errors_for_file = sum(report[error] for error in error_types)

        print(f"{filename} :: +{total_errors_for_file}")
        for error in error_types:
            print(f"   +{report[error]} :: {error.errortype}")
        print()
        print()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("previous_report")
    parser.add_argument("new_report")
    args = parser.parse_args()

    report, changes = compare_reports(args.previous_report, args.new_report)

    if changes > 0:
        print_changes(report)
        sys.exit(changes)


if __name__ == "__main__":
    main()
