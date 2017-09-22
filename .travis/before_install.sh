#!/usr/bin/env sh

.travis/download_geth.sh
.travis/download_solc_${TRAVIS_OS_NAME}.sh

if [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
    for tool in automake libtool pkg-config libffi gmp openssl node ; do
        brew install ${tool} || brew upgrade ${tool}
    done

    curl -O https://bootstrap.pypa.io/get-pip.py
    python get-pip.py --user
fi
