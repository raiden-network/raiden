set -e
set -x

CACHE_DIR="${HOME}/lint-cache"
mkdir -p $(basedir $old_report)

old_report="${CACHE_DIR}/previous"
new_report=$(mktemp)

pylint \
    --load-plugins=tools.pylint.gevent_checker,assert_checker \
    raiden/ tools/scenario-player/ > ${new_report} || true

exit_code=0
if [[ -e "${old_report}" ]]; then
    new_error_count=$(wc -l "${new_report}")
    previous_error_count=$(wc -l "${old_report}")

    if [[ $new_error_count -gt $previous_error_count ]]; then
        diff ${old_report} ${new_report}

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
            exit_code=1
        fi

        # DO NOT overwrite the old report in the cache, we want to keep the
        # version with the lower number of errors
    else
        # This PR fixed errors, move the new report over the old one to enforce
        # a new lower bound on the number of errors
        mv ${new_report} ${old_report}
    fi
else
    # First run, save the report to compare on subsequent runs
    mv ${new_report} ${old_report}
fi

exit ${exit_code}
