#!/usr/bin/env sh

DATADIR=$(mktemp -d)

echo $DATADIR

GETH="geth --datadir $DATADIR"

mkdir -p $DATADIR

./config_builder.py genesis 1 127.0.0.1 > $DATADIR/genesis.json

$GETH init $DATADIR/genesis.json

echo "\n" > $DATADIR/passwordfile
python -c "print '1' * 64" > $DATADIR/importkey

$GETH --password $DATADIR/passwordfile account import $DATADIR/importkey

$GETH --minerthreads 1 --rpc --mine --etherbase 0 --nodiscover --unlock 0 --password $DATADIR/passwordfile 2> $DATADIR/output.log& 

GETH_PID=$!

echo "Starting deployment. If geth needs to build its DAG first, this could take a bit longer..."

cd ..
make deploy > $DATADIR/deployments.txt
cd -

kill -15 $GETH_PID
sleep 5

LASTBLOCK=$(cat $DATADIR/output.log |grep "Mined block"|cut -d'#' -f2|cut -d' ' -f1|tail -n 1)

$GETH dump $LASTBLOCK > state_dump.json 
echo "Blockchain written to state_dump.json"

REGISTRY_ADDRESS=$(cat $DATADIR/deployments.txt |grep Deployed|grep Registry|grep -v Endpoint|cut -d ':' -f3|cut -b4-)
DISCOVERY_ADDRESS=$(cat $DATADIR/deployments.txt |grep Deployed|grep Endpoint|cut -d ':' -f3|cut -b4-)

echo "Contract flags for raiden:"

echo "--registry_contract_address $REGISTRY_ADDRESS"
echo "--discovery_contract_address $DISCOVERY_ADDRESS" 
