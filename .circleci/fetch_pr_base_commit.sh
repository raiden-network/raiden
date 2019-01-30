#!/bin/bash

if [[ -n "${CIRCLE_PR_NUMBER}" ]]; then
    # If this is a PR get the base commit from the GitHub API
    PR_DETAILS_URL="https://api.github.com/repos/${CIRCLE_PROJECT_USERNAME}/${CIRCLE_PROJECT_REPONAME}/pulls/${CIRCLE_PR_NUMBER}"
    BASE_COMMIT=$(curl ${PR_DETAILS_URL} | jq -r .base.sha)
    if [[ ${BASE_COMMIT} =~ ^[0-9a-zA-Z]{40}$ ]]; then
        echo ${BASE_COMMIT} > ~/.local/BASE_COMMIT
    fi
fi
