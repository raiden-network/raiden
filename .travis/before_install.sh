#!/usr/bin/env sh

.travis/prepare_os_${TRAVIS_OS_NAME}.sh
.travis/download_geth.sh
.travis/download_solc_${TRAVIS_OS_NAME}.sh
