#!/usr/bin/env bash

set -ex

if [ -z ${BLOCKCHAIN_TYPE} ] && [[ ${TRAVIS_EVENT_TYPE} == "cron" ]]; then
    BLOCKCHAIN_TYPE="geth"
elif [ -z ${BLOCKCHAIN_TYPE} ]; then
    # FIXME: change to "tester" once the test failures are fixed
    BLOCKCHAIN_TYPE="geth"
fi

if [[ ${RUN_COVERAGE} = run_coverage ]]; then
    TEST_RUNNER="coverage run -m py.test"
elif [[ ${RUN_COVERAGE} = no_coverage ]]; then
    TEST_RUNNER="py.test"
fi

${TEST_RUNNER} \
    -Wd \
    --travis-fold=always \
    --log-config='raiden:DEBUG' \
    --random \
    -v \
    --showlocals \
    --blockchain-type=${BLOCKCHAIN_TYPE} \
    ${TRANSPORT_OPTIONS} \
    ${TEST}
