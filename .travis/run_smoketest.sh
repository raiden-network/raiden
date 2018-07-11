#!/usr/bin/env bash

set -e
set -x

if [[ -z ${RUN_SYNAPSE} ]]; then
    raiden --transport=udp smoketest
else
    raiden --transport=matrix smoketest --local-matrix="${HOME}/.bin/run_synapse.sh"
fi
