#!/usr/bin/env bash

set -ex

if [[ ${TRAVIS_EVENT_TYPE} == "cron" ]]; then
    BLOCKCHAIN_TYPE="geth"
else
    # FIXME: change to "tester" once the test failures are fixed
    BLOCKCHAIN_TYPE="geth"
fi

coverage run \
    -m py.test \
    -Wd \
    --travis-fold=always \
    --log-config='raiden:DEBUG' \
    --random \
    -v \
    --blockchain-type=${BLOCKCHAIN_TYPE} \
    ${TRANSPORT_OPTIONS} \
    ${TEST}
