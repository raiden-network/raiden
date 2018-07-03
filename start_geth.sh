#!/bin/bash

geth --nodekeyhex f68952f08b60b79a5dbd3ec754ee33e6e52101fcf1d8055fc89979c253b14832 --nat=none --port 29871 --rpcport 29870 --bootnodes enode://4fd93e573bf5949fadaf092a1e49341267902e76d886bd02360a550df77672b6d1a1c78c9d31f542d1fc6633d8cc85a0535da432c221560e6e1f32dc8b25b9c9@127.0.0.1:29871 --unlock 0 --nodiscover --rpc --rpcapi eth,net,web3 --rpcaddr 0.0.0.0 --networkid 627 --verbosity 6 --datadir /tmp/pytest-of-psz/pytest-psz/f68952f0 --password /tmp/pytest-of-psz/pytest-psz/f68952f0/pw

