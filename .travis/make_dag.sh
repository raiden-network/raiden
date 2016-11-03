#!/bin/sh

set -e

if [ ! -d $HOME/.ethash ]; then
    mkdir -p $HOME/.ethash
    geth makedag 0 $HOME/.ethash
else
    echo 'Using cached dag'
fi
