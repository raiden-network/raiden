#!/usr/bin/env sh

if [[ "$TRAVIS_OS_NAME" == "osx" ]];
    export PATH=$PATH:$HOME/Library/Python/2.7/bin;
fi

"./.travis/download_geth.sh"
"./.travis/download_solc.sh"
