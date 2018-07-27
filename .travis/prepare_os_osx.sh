#!/usr/bin/env bash

set -e
set -x

for tool in automake gmp leveldb libffi libtool node openssl pkg-config python3; do
    brew install ${tool} || brew upgrade ${tool} || true
done

# create links so python 3 tools get used
ln -sf /usr/local/bin/pip3 $HOME/.bin/pip
ln -sf /usr/local/bin/python3 $HOME/.bin/python

# some debug info
ls -la $HOME/.bin
uname -a
sw_vers
xcodebuild -version
