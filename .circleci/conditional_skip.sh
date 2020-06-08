#!/bin/bash

# Seems that circle calls this script with -e and we don't want
# grep failure to stop the build
set +e

SKIP_TAG="\[skip tests\]"

# shellcheck disable=SC2154
if [[ -n ${CIRCLE_TAG} ]]; then
    # TAG build - never skip those
    echo "Tagged commit, not skipping build"
    exit 0
fi

# shellcheck disable=SC2154
if [[ -z ${CIRCLE_PR_NUMBER} ]]; then
    # Not a PR, also never skip
    echo "Not a PR, not skipping build"
    exit 0
fi

if [[ -a ~/.local/BASE_COMMIT ]]; then
    # The is a PR and we know the base commit (see fetch_pr_base_commit.sh)
    LOG_RANGE="$(cat ~/.local/BASE_COMMIT)..${CIRCLE_SHA1:?}"
else
    # Otherwise just look at the HEAD commit
    LOG_RANGE="-1"
fi

git log --pretty="- %h %B" ${LOG_RANGE} | grep "${SKIP_TAG}"

if [[ ${PIPESTATUS[1]} == 0 ]]; then
    echo "Skip tag found - skipping build"
    circleci step halt
fi
set -e
