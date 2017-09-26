#!/usr/bin/env bash

set -e
set -x

for tool in automake libtool pkg-config libffi gmp openssl node ; do
    brew install ${tool} || brew upgrade ${tool}
done

curl -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py --user
