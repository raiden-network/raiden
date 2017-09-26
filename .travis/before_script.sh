#!/usr/bin/env bash

set -e
set -x

flake8 raiden/ tools/
python setup.py check --restructuredtext --strict
raiden smoketest
