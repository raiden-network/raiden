#!/usr/bin/env bash

set -ex

HOST="$1"
FINGERPRINT="$2"

PUBKEY=$(mktemp)

ssh-keyscan -H ${HOST} > ${PUBKEY} 2>/dev/null

if [[ $(ssh-keygen -l -f ${PUBKEY} | cut -d ' ' -f 2) != ${FINGERPRINT} ]]; then
    echo "Warning fingerprint mismatch while fetching public key for ${HOST}"
    exit 1
fi

cat ${PUBKEY} >> ~/.ssh/known_hosts
