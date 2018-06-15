#!/usr/bin/env sh

set -e
set -x

make lint
python setup.py check --restructuredtext --strict
if [ -z "$RUN_SYNAPSE" ]; then
    raiden smoketest
else
    raiden --transport=matrix smoketest --local-matrix="${HOME}/.bin/run_synapse.sh"
fi
