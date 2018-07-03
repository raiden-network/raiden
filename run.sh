#!/bin/bash

#mkdir -p $HOME/.bin
#export PATH=$PATH:$HOME/.bin
#./.travis/before_install.sh
#./.travis/install.sh
#./.travis/before_script.sh
coverage run -m py.test -Wd --travis-fold=always -vvvvvv --log-config='raiden:DEBUG' --random --blockchain-type=geth $TRANSPORT_OPTIONS $TEST

