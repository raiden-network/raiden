#!/usr/bin/env sh
flake8 raiden/ tools/
python setup.py check --restructuredtext --strict
raiden smoketest
