#!/bin/sh

set -e

mkdir -p $HOME/.ethash

if [ ! -s $HOME/.ethash/full-R23-0000000000000000 ]; then
    geth makedag 0 $HOME/.ethash
else
    echo 'Using cached dag'
    ls $HOME/.ethash
fi
