#!/usr/bin/env sh

set -e
set -x
.travis/prepare_os_${TRAVIS_OS_NAME}.sh

.travis/download_solc.sh

solc --version


.travis/download_geth.sh
