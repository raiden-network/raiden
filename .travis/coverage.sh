#!/usr/bin/env bash

# Script to determine whether to run `coverage` or not. Its output is intended to be set to a global
# env variable `RUN_COVERAGE`, that will be tested for in consecutive steps.

set -e
set -x

PR_MSG="$(git log --format=%B -n 1 $(echo ${TRAVIS_COMMIT_RANGE} | cut -d '.' -f4))"

# Conditions
# - HEAD commit is tagged [ci coverage]
# - master branch AND cron job

if [[ "${PR_MSG}" =~ "[ci coverage]" || "${TRAVIS_EVENT_TYPE}" == "cron" && "${TRAVIS_BRANCH}" == "master" ]]; then
    echo run_coverage
else
    echo no_coverage
fi
