#!/usr/bin/env bash

set -e
set -x

PYTHON_36_FORMULA=https://raw.githubusercontent.com/Homebrew/homebrew-core/f2a764ef944b1080be64bd88dca9a1d80130c558/Formula/python.rb
NODE_10_URL=https://nodejs.org/download/release/v10.12.0/node-v10.12.0-darwin-x64.tar.xz

# Don't spam logs
brew update > /dev/null

# Remove to prevent a slow update cascade
brew uninstall postgis

for tool in automake gmp leveldb libffi libtool openssl pkg-config sqlite3; do
    brew install ${tool} || brew upgrade ${tool} || true
done

# Pin to python3.6 for the time being
# do this after the other packages to ensure we overwrite a (through dependencies) possibly installed newer version
brew install ${PYTHON_36_FORMULA} || brew unlink python && brew install --force ${PYTHON_36_FORMULA}

# create links so python 3 tools get used
ln -sf /usr/local/bin/pip3 $HOME/.bin/pip
ln -sf /usr/local/bin/python3 $HOME/.bin/python

# Download node
wget ${NODE_10_URL}
node_dl_file=$(basename ${NODE_10_URL})
tar xvf $(basename ${NODE_10_URL})
rm ${node_dl_file}
base="$(pwd)/${node_dl_file%.tar.xz}"
ln -sf ${base}/bin/node $HOME/.bin/
ln -sf ${base}/bin/npm $HOME/.bin/
ln -sf ${base}/bin/npx $HOME/.bin/

# Remove all other node/npm versions
rm /Users/travis/.nvm/versions/node/*/bin/{node,npm}

# some debug info
ls -la $HOME/.bin
uname -a
sw_vers
xcodebuild -version
