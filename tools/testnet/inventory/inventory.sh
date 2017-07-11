#!/bin/bash

# cross platform compatible way to get temp dir location
TMP=$(dirname $(mktemp -u))
# "Cache" state for one minute
STATE_FILE="${TMP}/raiden-testnet-$(date +%Y%m%d%H%M).tfstate"
if [ ! -f ${STATE_FILE} ]; then
    terraform state pull > ${STATE_FILE}
fi
exec terraform-inventory "$@" ${STATE_FILE}
