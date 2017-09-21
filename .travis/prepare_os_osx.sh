#!/usr/bin/env bash

set -e
set -x

for tool in automake libtool pkg-config libffi gmp openssl ; do
    brew install ${tool} || brew upgrade ${tool} || true
done

if [ ! -x $HOME/.bin/geth-${GETH_VERSION}-${TRAVIS_OS_NAME} ]; then
    mkdir -p $HOME/.bin

    TEMP=$(mktemp -d 2>/dev/null || mktemp -d -t 'nodetmp')
    cd $TEMP
    curl -L https://nodejs.org/dist/v6.11.3/node-v6.11.3-darwin-x64.tar.gz > node.tgz
    tar xzf node.tgz

    cd node*
    install -m 755 bin/npm $HOME/.bin/npm
    install -m 755 bin/node $HOME/.bin/node
fi

curl -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py --user
