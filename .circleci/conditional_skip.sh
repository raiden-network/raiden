#!/bin/bash

SKIP_TAG="\[skip tests\]"

if [[ -n "${CIRCLE_PR_NUMBER}" ]]; then
    # If this is a PR get the base commit from the GitHub API
    BASE_COMMIT=$(curl \
        -H "Authorization: token ${GITHUB_TOKEN_RO}" \
        https://api.github.com/repos/${CIRCLE_PROJECT_USERNAME}/${CIRCLE_PROJECT_REPONAME}/pulls/${CIRCLE_PR_NUMBER} \
        | jq -r .base.sha)
    LOG_RANGE="${BASE_COMMIT}..${CIRCLE_SHA1}"
else
    # Otherwise just look at the HEAD commit
    LOG_RANGE="-1"
fi

git log --pretty="- %h %B" ${LOG_RANGE} | grep "${SKIP_TAG}"

if [[ ${PIPESTATUS[1]} == 0 ]]; then
    echo Skip tag found - skipping build
    circleci step halt
fi
