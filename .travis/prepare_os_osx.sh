#!/usr/bin/env bash

set -e
set -x

for tool in automake libtool pkg-config libffi gmp openssl node python3; do
    brew install ${tool} || brew upgrade ${tool} || true
done

# some debug info
ls -la $HOME/.bin
uname -a
sw_vers
xcodebuild -version
