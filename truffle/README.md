## Truffle for local setups
There are some truffle-specific `make`-goals. They are intended to help with deployment (and testing). In order to avoid installing `npm`, truffle is used from inside an container. To get you started, you will need to set up the container:
```
make build-truffle-container
```
From then on, you can call
```
make compile
```
to compile all solidity files in `raiden/smart_contracts`.
### Setup a local blockchain

#### Hydrachain
If you want to deploy the code in a hydrachain node, you need to start the blockchain:
```
make blockchain
```
# you should tail the file `blockchain.log` in order to see the network is up:
````
tail blockchain.log |grep "CachedBlock(\#10"
2016-05-19 11:38:22,698 INFO:hdc.chainservice   new head head=<CachedBlock(#10 712fc415)>
2016-05-19 11:38:22,722 INFO:hdc.chainservice   new head head=<CachedBlock(#10 712fc415)>
2016-05-19 11:38:22,757 INFO:hdc.chainservice   new head head=<CachedBlock(#10 712fc415)>
```

#### go-ethereum
Alternatively, there is also the option to start a go-ethereum (`geth`) cluster:
```
make blockchain-geth
```

```
# now you're ready to (compile and) deploy the contracts
make deploy

# to start over:
make stop
```
