#!/usr/bin/env sh

set -e
set -x

if [ -z "$RUN_SYNAPSE" ]; then
    raiden smoketest
else
    raiden --transport=matrix smoketest --local-matrix="${HOME}/.bin/run_synapse.sh"
fi
