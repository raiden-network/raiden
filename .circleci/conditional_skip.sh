#!/bin/bash

SKIP_TAG="\[skip tests\]"

if [[ -a ~/.local/BASE_COMMIT ]]; then
    # The is a PR and we know the base commit (see fetch_pr_base_commit.sh)
    LOG_RANGE="$(cat ~/.local/BASE_COMMIT)..${CIRCLE_SHA1}"
else
    # Otherwise just look at the HEAD commit
    LOG_RANGE="-1"
fi

git log --pretty="- %h %B" ${LOG_RANGE} | grep "${SKIP_TAG}"

if [[ ${PIPESTATUS[1]} == 0 ]]; then
    echo Skip tag found - skipping build
    circleci step halt
fi
