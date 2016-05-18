setup:

    make build-truffle-container

deploy all contracts from `raiden/truffle/contracts/*.sol`:

    make blockchain
    sleep 20
    make deploy

clean up afterwards:
    
    make stop
