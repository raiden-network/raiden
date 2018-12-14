#!/usr/bin/env bash

set -e
set -x

.travis/prepare_os_${TRAVIS_OS_NAME}.sh

.travis/download_solc.sh
.travis/download_geth.sh
