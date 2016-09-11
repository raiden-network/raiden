#!/bin/bash

NODES_PER_MACHINE=2

# list of IPs
IP_ADDRESSES="127.0.0.1"

DATADIR=ethereum
TMPDIR=$(mktemp -d --tmpdir=.)
GETH="geth --datadir ${DATADIR}"

GENESIS_FILE=${DATADIR}/genesis.json
SCENARIO_FILE=${DATADIR}/scenario.json
GETH_COMMANDS_FILE=${DATADIR}/geth_commands.json
STATE_FILE=${TMPDIR}/state_dump.json

mkdir -p ${DATADIR} ${TMPDIR}

./config_builder.py build_scenario ${NODES_PER_MACHINE} ${IP_ADDRESSES} > ${SCENARIO_FILE}

./config_builder.py geth_commands ${DATADIR} ${IP_ADDRESSES} > ${GETH_COMMANDS_FILE}

sed 's/^.*\(\[\"enode:.*\]\),.*$/\1/g' ${GETH_COMMANDS_FILE} > ${DATADIR}/static-nodes.json

mkdir -p ${DATADIR}/keystore
./config_builder.py account_file > ${DATADIR}/keystore/default.json

./config_builder.py full_genesis ${NODES_PER_MACHINE} ${IP_ADDRESSES} --scenario ${SCENARIO_FILE} > ${GENESIS_FILE}

sed 's/^.*\"raidenFlags\": \"\([^"]*\).*$/\1/g' ${GENESIS_FILE} > ${DATADIR}/raiden_flags.txt

# for each node add a private key (will be iterated over to pass to raiden)
./config_builder.py accounts ${NODES_PER_MACHINE} ${IP_ADDRESSES} > ${DATADIR}/raiden_nodes.json

geth --datadir ${DATADIR} init ${GENESIS_FILE}
