#!/usr/bin/env sh

set -e
set -x

.travis/download_solc.sh

solc --version


.travis/prepare_os_${TRAVIS_OS_NAME}.sh
.travis/download_geth.sh
