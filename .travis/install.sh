#!/usr/bin/env sh
pip install -U pip wheel coveralls "coverage<4.4"
pip install pytest-travis-fold
pip install flake8
pip install readme_renderer
pip install -r requirements-dev.txt
pip install .
