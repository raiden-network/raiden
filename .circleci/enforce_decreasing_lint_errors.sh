#!/usr/bin/env bash

set -e
set -x

# For the first build the PR's base branch will work as a baseline,
# subsequent reports will be against the PR itself. Because of
# this, it is possible for a PR to undo linting fixes from another.
# Example:
#
# 1. PR1 is opened, it does not fix any linting errors
# 2. PR2 is opened against the same base branch, and merged, it
#    fixes linting errors
# 3. PR1 is rebased on the base branch. This may introduce as many
#    errors as PR2 fixed without failling the build (because the
#    baseline is outdated).
# 4. PR1 is merged.
#
# This is fine, at least the number of errors doesn't increase.
# Additionally, because on step 4 above PR1 was merged, the base
# branch itself got more linting errors, for this reason topic
# branches (e.g. master or develop) should not break if linting
# errors increase.
if [[ ! -e ~/.local/BASE_COMMIT ]]; then
    exit 0
fi

function compare_pylint_reports() {
    if [[ $# -ne 2 ]]; then
        echo "compare_pylint_reports was not properly called, it requires two arguments, $# given"
        exit 1
    fi

    new=$1
    old=$2

    if [[ ! -e "${new}" ]]; then
        echo "compare_pylint_reports was not properly called, new report ${new} is missing."
        exit 1
    fi

    if [[ -e "${old}" ]]; then
        new_error_count=$(wc -l "${new}" | cut '-d ' -f1)
        previous_error_count=$(wc -l "${old}" | cut '-d ' -f1)

        if [[ $new_error_count -gt $previous_error_count ]]; then
            diff ${old} ${new}

            # DO NOT overwrite the old report in the cache, we want to keep the
            # version with the lower number of errors
        else
            # This PR fixed errors, move the new report over the old one to enforce
            # a new lower bound on the number of errors
            mv ${new} ${old}
        fi
    else
        # Save the report to compare on subsequent runs
        mv ${new} ${old}
    fi
}

function compare_mypy_reports() {
    if [[ $# -ne 2 ]]; then
        echo "compare_mypy_reports was not properly called, it requires two arguments, $# given"
        exit 1
    fi

    new=$1
    old=$2

    if [[ ! -e "${new}" ]]; then
        echo "compare_mypy_reports was not properly called, new report ${new} is missing."
        exit 1
    fi

    if [[ -e "${old}" ]]; then
        if ! ./.circleci/lint_report.py ${old} ${new}; then
            # DO NOT overwrite the old report in the cache, we want to keep the
            # version with the lower number of errors
            #
            # If this PR fixed errors, move the new report over the old one to
            # enforce a new lower bound on the number of errors
            mv ${new} ${old}
        fi
    else
        # Save the report to compare on subsequent runs
        mv ${new} ${old}
    fi
}

CACHE_DIR="${HOME}/lint-cache"
mkdir -p "${CACHE_DIR}"

old_report_pylint="${CACHE_DIR}/pylint"
old_report_mypy="${CACHE_DIR}/mypy"
new_report_pylint=$(mktemp)
new_report_mypy=$(mktemp)

pylint --jobs=0 \
    --load-plugins=tools.pylint.gevent_checker,tools.pylint.assert_checker \
    raiden/ tools/scenario-player/ > ${new_report_pylint} || true

mypy --config-file /dev/null --strict --disallow-subclassing-any \
    --disallow-any-expr --disallow-any-decorated --disallow-any-explicit \
    --disallow-any-generics raiden tools > ${new_report_mypy} || true

exit_code=0

if ! compare_pylint_reports "${new_report_pylint}" "${old_report_pylint}"; then
    exit_code=1
fi

if ! compare_mypy_reports "${new_report_mypy}" "${old_report_mypy}"; then
    exit_code=1
fi

exit ${exit_code}
