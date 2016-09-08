### Setup a local blockchain

#### go-ethereum
There is the option to start a go-ethereum (`geth`) cluster:
```
make blockchain-geth
```

```
# now you're ready to (compile and) deploy the contracts
make deploy

# to start over:
make stop-geth
```
