#!/usr/bin/env bash

# Usage:
# ./solc [options] inputfile > outfile

# Notes:
# - file i/o is limited to the current directory
# - this works with the pyethereum solc_wrapper

docker run -i --rm --user $(id -u):$(id -g) -v $(pwd):/tmp --workdir /tmp ethereum/solc:${SOLC_VERSION} $@