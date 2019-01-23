#!/usr/bin/env bash

set -e
set -x

INSTALL_OPT=""
if [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
    # install into user dir on macos to avoid sudo
    INSTALL_OPT="--user"
fi

pip install ${INSTALL_OPT} --upgrade pip wheel
pip install ${INSTALL_OPT} pytest-travis-fold
pip install ${INSTALL_OPT} -c constraints.txt --upgrade --upgrade-strategy eager -r requirements-dev.txt
pip install ${INSTALL_OPT} -c constraints.txt -e .

if [[ ${RUN_COVERAGE} = run_coverage ]]; then
    pip install ${INSTALL_OPT} --upgrade coveralls
fi

pip list --outdated
