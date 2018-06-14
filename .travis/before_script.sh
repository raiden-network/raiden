#!/usr/bin/env sh

set -e
set -x

make lint
python setup.py check --restructuredtext --strict
raiden smoketest
