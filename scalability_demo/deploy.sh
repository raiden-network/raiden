#!/bin/bash

NODES_PER_MACHINE=4

# list of IPs
IP_ADDRESSES="127.0.0.1"

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

# TODO: save this to config file
REGISTRY_ADDRESS=$(grep '\"Registry' ${TMPDIR}/deployment.txt | cut -d: -f2 | tr -d '" ')
DISCOVERY_ADDRESS=$(grep EndpointRegistry ${TMPDIR}/deployment.txt | cut -d: -f2 | tr -d '" ')

echo "Contract flags for raiden:"

echo "--registry_contract_address ${REGISTRY_ADDRESS}"
echo "--discovery_contract_address ${DISCOVERY_ADDRESS}"

./config_builder.py merge ${STATE_FILE} ${GENESIS_FILE} > ${TMPDIR}/complete_genesis.json

cp ${TMPDIR}/complete_genesis.json ${GENESIS_FILE}

# TODO copy genesis file and run geth init on all nodes
${GETH} init ${DATADIR}/genesis.json

# add default account for the `geth` nodes
# TODO needs to run on all nodes
mkdir -p ${DATADIR}/keystore
./config_builder.py account_file > ${DATADIR}/keystore/1.json

# create run commands for all `geth` nodes in the cluster
./config_builder.py geth_commands ${DATADIR} ${IP_ADDRESSES}

# TODO
#kubectl run geth --image=geth --port=8545

# TODO: pass --env and pass -- args
#kubectl run -f raiden.yaml
