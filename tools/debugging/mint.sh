#!/usr/bin/bash

set -e

info() {
    printf "$(tput bold)$(tput setaf 4) -> $1$(tput sgr0)\n"
}

die() {
    printf "$(tput bold)$(tput setaf 1) -> $1$(tput sgr0)\n" >&2
    exit 1
}

require_bin() {
    hash $1 2> /dev/null || {
        die "Required binary was not found ${1}"
    }
}

require_bin jq
require_bin http
require_bin parallel

[ $# -lt 2 ] && die "${0} <token_address> <raiden_server>+"

UINT256_MAX=115792089237316195423570985008687907853269984665640564039457584007913129639935
UINT128_MAX=340282366920938463463374607431768211455
UINT64_MAX=18446744073709551615
MINT_AMOUNT=$UINT64_MAX

mint(){
    server=$1
    token=$2
    mint_amount=$3

    address_url="http://${server}/api/v1/address"
    mint_url="http://${server}/api/v1/_testing/tokens/${token}/mint"

    node_address=$(http GET $address_url | jq .our_address -r)

    http --ignore-stdin --timeout=600 POST $mint_url to=$node_address value=$mint_amount
}


TOKEN_ADDRES=$1
shift

# export the symbol to allow the subshell spawned by parallel to use it
export -f mint 

for server in $@; do
    echo mint $server $TOKEN_ADDRES $MINT_AMOUNT
done | parallel
