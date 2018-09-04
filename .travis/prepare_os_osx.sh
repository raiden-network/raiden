#!/usr/bin/env bash

set -e
set -x

PYTHON_36_FORMULA=https://raw.githubusercontent.com/Homebrew/homebrew-core/f2a764ef944b1080be64bd88dca9a1d80130c558/Formula/python.rb

# Pin to python3.6 for the time being
brew install ${PYTHON_36_FORMULA} || brew upgrade ${PYTHON_36_FORMULA}

for tool in automake gmp leveldb libffi libtool node openssl pkg-config; do
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
