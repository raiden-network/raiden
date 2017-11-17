#!/usr/bin/env sh

set -e
set -x

flake8 raiden/ tools/
python setup.py check --restructuredtext --strict
raiden smoketest
