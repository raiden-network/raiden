#!/bin/bash

NODES_PER_MACHINE=4

# list of IPs
IP_ADDRESSES="192.168.0.11 192.168.0.13"

DATADIR=ethereum
TMPDIR=$(mktemp -d --tmpdir=.)
GETH="geth --datadir ${DATADIR}"

GENESIS_FILE=${DATADIR}/genesis.json
STATE_FILE=${TMPDIR}/state_dump.json

mkdir -p ${DATADIR} ${TMPDIR}

# create geth private network
./config_builder.py genesis ${NODES_PER_MACHINE} ${IP_ADDRESSES} > ${GENESIS_FILE}

${GETH} init ${GENESIS_FILE}

echo "\n" > ${DATADIR}/passwordfile
python -c "print '1' * 64" > ${DATADIR}/importkey

${GETH} --password ${DATADIR}/passwordfile account import ${DATADIR}/importkey

${GETH} --minerthreads 1 --rpc --mine --etherbase 0 --nodiscover --unlock 0 --password ${DATADIR}/passwordfile 2> ${TMPDIR}/output.log &
GETH_PID=$!

echo "Starting deployment. If geth needs to build its DAG first, this could take a bit longer..."

./deploy.py > ${TMPDIR}/deployment.txt

kill -15 ${GETH_PID}
sleep 5

LASTBLOCK=$(cat ${TMPDIR}/output.log |grep "Mined block"|cut -d'#' -f2|cut -d' ' -f1|tail -n 1)

${GETH} dump ${LASTBLOCK} > ${STATE_FILE}
echo "Blockchain written to state_dump.json"

REGISTRY_ADDRESS=$(grep '\"Registry' ${TMPDIR}/deployment.txt | cut -d: -f2 | tr -d '" ,')
DISCOVERY_ADDRESS=$(grep EndpointRegistry ${TMPDIR}/deployment.txt | cut -d: -f2 | tr -d '" ,')

echo ""
echo "Contract flags for raiden:"

echo "--registry_contract_address ${REGISTRY_ADDRESS}"
echo "--discovery_contract_address ${DISCOVERY_ADDRESS}"
echo ""

./config_builder.py merge ${STATE_FILE} ${GENESIS_FILE} > ${TMPDIR}/complete_genesis.json

cp ${TMPDIR}/complete_genesis.json ${GENESIS_FILE}

# ---------------------------------------------------------------------------------------
# build geth commands (for every node)

${GETH} init ${DATADIR}/genesis.json

mkdir -p ${DATADIR}/keystore
./config_builder.py account_file > ${DATADIR}/keystore/1.json

./config_builder.py create_static_nodes ${IP_ADDRESSES} > ${DATADIR}/static-nodes.json

# TODO 1) copy genesis.json, keystore/1.json, static-nodes.json to every geth node
#      2) run geth init for every node

# create run commands for all `geth` nodes in the cluster
./config_builder.py geth_commands ${DATADIR} ${IP_ADDRESSES}

# ---------------------------------------------------------------------------------------
# build raiden commands

RAIDEN_OPTS = "--registry_contract_address ${REGISTRY_ADDRESS} --discovery_contract_address ${DISCOVERY_ADDRESS}"
echo ${RAIDEN_OPTS} > ${DATADIR}/raiden_opts.txt

# for each node add a private key (will be iterated over to pass to raiden)
./config_builder.py accounts ${NODES_PER_MACHINE} ${IP_ADDRESSES} > ${DATADIR}/raiden_nodes.json

# ---------------------------------------------------------------------------------------
# start cluster proper

# TODO
#kubectl run geth --image=geth --port=8545

# TODO: pass --env and pass -- args
#kubectl run -f raiden.yaml
