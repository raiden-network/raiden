#!/bin/bash

# TODO
kubectl run geth --image=geth --port=8545

# TODO: pass --env and pass -- args
kubectl run -f raiden.yaml
