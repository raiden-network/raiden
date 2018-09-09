#!/usr/bin/env bash

set -ex

TRAVIS_COMMIT_MSG=`git log --format=%B --no-merges --topo-order -n 1`
if [[ -z ${BLOCKCHAIN_TYPE} && ${TRAVIS_EVENT_TYPE} == "cron" ]]; then
    BLOCKCHAIN_TYPE="geth"
elif [[ -z ${BLOCKCHAIN_TYPE} && "${TRAVIS_COMMIT_MSG}" =~ '[tester]' ]]; then
    BLOCKCHAIN_TYPE="tester"
elif [[ -z ${BLOCKCHAIN_TYPE} ]]; then
    BLOCKCHAIN_TYPE="geth"
fi

echo MSG=${TRAVIS_COMMIT_MSG}, BC=${BLOCKCHAIN_TYPE}

if [[ -z ${RUN_SYNAPSE} ]]; then
    raiden --transport=udp smoketest
else
    raiden --transport=matrix smoketest --local-matrix="${HOME}/.bin/run_synapse.sh"
fi
