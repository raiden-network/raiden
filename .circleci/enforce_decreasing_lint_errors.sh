set -e
set -x

function compare_reports() {
    if [[ $# -ne 2 ]]; then
        echo "compare_reports was not properly called, it requires two arguments, $# given"
        exit 1
    fi

    new=$1
    old=$2

    if [[ ! -e "${new}" ]]; then
        echo "compare_reports was not properly called, new report ${new} is missing."
        exit 1
    fi

    if [[ -e "${old}" ]]; then
        new_error_count=$(wc -l "${new}")
        previous_error_count=$(wc -l "${old}")

        if [[ $new_error_count -gt $previous_error_count ]]; then
            diff ${old} ${new}

            # For the first build master will work as a baseline, subsequent reports
            # will be against the PR itself. Because of this, it is possible for a PR
            # to undo linting fixes from another. Example:
            #
            # 1. PR1 is opened, it does not fix any linting errors
            # 2. PR2 is opened, and merged, it fixes linting errors
            # 3. PR1 is rebased on master. This may introduce as many errors as PR2
            #    fixed without failling the build.
            # 4. PR1 is merged.
            #
            # This is fine, at least the number of errors doesn't increase.
            # Additionally, because on step 4 above PR1 was merged on msater, master
            # itself got more linting errors, for this reason master should not break
            # if linting errors increase.
            if [[ "${CIRCLE_BRANCH}" != "master" ]]; then
                return 1
            fi

            # DO NOT overwrite the old report in the cache, we want to keep the
            # version with the lower number of errors
        else
            # This PR fixed errors, move the new report over the old one to enforce
            # a new lower bound on the number of errors
            mv ${new} ${old}
        fi
    else
        # First run, save the report to compare on subsequent runs
        mv ${new} ${old}
    fi
}

CACHE_DIR="${HOME}/lint-cache"
mkdir -p "${CACHE_DIR}"

old_report_pylint="${CACHE_DIR}/pylint"
old_report_mypy="${CACHE_DIR}/pylint"
new_report_pylint=$(mktemp)
new_report_mypy=$(mktemp)

pylint \
    --load-plugins=tools.pylint.gevent_checker,assert_checker \
    raiden/ tools/scenario-player/ > ${new_report} || true

mypy raiden tools > ${new_report_mypy} || true

if ! compare_reports "${new_report_pylint}" "${old_report_pylint}"; then
    exit_code=1
fi

if ! compare_reports "${new_report_mypy}" "${old_report_mypy}"; then
    exit_code=1
fi

exit ${exit_code}
