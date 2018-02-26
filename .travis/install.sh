#!/usr/bin/env sh

set -e
set -x

INSTALL_OPT=""
if [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
    # install into user dir on macos to avoid sudo
    INSTALL_OPT="--user"
fi

pip install ${INSTALL_OPT} -U pip wheel coveralls "coverage<4.4"
pip install ${INSTALL_OPT} pytest-travis-fold
pip install ${INSTALL_OPT} readme_renderer
pip install ${INSTALL_OPT} pyinstaller
pip install ${INSTALL_OPT} -r requirements-dev.txt
pip install ${INSTALL_OPT} -e .
