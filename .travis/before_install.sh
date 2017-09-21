#!/usr/bin/env sh

"./.travis/download_geth.sh"
"./.travis/download_solc.sh"

if [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
    curl -O https://bootstrap.pypa.io/get-pip.py
    python get-pip.py --user
fi
