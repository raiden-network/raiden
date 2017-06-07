#!/usr/bin/env bash

set -e

mkdir -p $HOME/.ethash

# this will generate the DAG once, travis is configured to cache it and
# subsequent calls will not regenerate
ls -alhR $HOME/.ethash
geth makedag 0 $HOME/.ethash
