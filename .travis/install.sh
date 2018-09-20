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
pip install ${INSTALL_OPT} s3cmd
pip install ${INSTALL_OPT} pyinstaller
pip install ${INSTALL_OPT} -c constraints.txt --upgrade --upgrade-strategy eager -r requirements-dev.txt
pip install ${INSTALL_OPT} -c constraints.txt -e .

pip list --outdated
