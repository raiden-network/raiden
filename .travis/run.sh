#!/bin/bash

set -ex

if [[ ${TRAVIS_EVENT_TYPE} == "cron" ]]; then
    BLOCKCHAIN_TYPE="geth"
else
    BLOCKCHAIN_TYPE="eth-tester"
fi

coverage run \
    -m py.test \
    -Wd \
    --travis-fold=always \
    -vvvvvv \
    --log-config='raiden:DEBUG' \
    --random \
    --blockchain-type=${BLOCKCHAIN_TYPE} \
    ${TRANSPORT_OPTIONS} \
    ${TEST}
