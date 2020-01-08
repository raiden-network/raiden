tools
-----

- `parallel_tests.sh`: Tool to execute the test suite in parallel, useful to
  run multiple integration tests at the same time.
- `startcluster.py`: This tool will generate a genesis file with a few
  pre-funded accounts to be used as Raiden accounts, and then run a local
  Geth private chain, useful for debugging.
- `transfer_eth.py`: This is just a simple tool to send an eth transfer using
  the provided private key.

debugging
---------

- `mint.sh`: Tool to mint test tokens. Usage:

```sh
./mint.sh 0xf9BA8aDF7F7024D7de8eB37b4c981CFFe3C88Ea7 127.0.0.1:5001 127.0.0.1:5002 127.0.0.1:5000
```

The first argument is the test token with the `mintFor` function, the others
are endpoints of running Raiden nodes.

Note: Each of the running nodes must have test ETH on their accounts.

- `channels_with_minimum_balance.py`: Tool to open multiple channels. It needs
  a JSON file with the following format:


```json
{
    "networks": {
        "0xf9BA8aDF7F7024D7de8eB37b4c981CFFe3C88Ea7": [
            {
                "node1": "node0",
                "minimum_capacity1": 1130220,
                "node2": "node1",
                "minimum_capacity2": 1130220
            },
            {
                "node1": "node1",
                "minimum_capacity1": 1130220,
                "node2": "node2",
                "minimum_capacity2": 1130220
            }
        ]
    },
    "nodes": {
        "node0": {
            "address": "0x5c11cc525590d9Ff8C7E4Af1704A39Df6c3884b5",
            "endpoint": "http://127.0.0.1:5000"
        },
        "node1": {
            "address": "0xa9FA88442c404716623155d150c526D8F1ae82E5",
            "endpoint": "http://127.0.0.1:5001"
        },
        "node2": {
            "address": "0x9df878E37C4B851bbe44841e72299F6f317C685C",
            "endpoint": "http://127.0.0.1:5005"
        }
    }
}
```

Under `networks` we have the *token address*, and under each token address
there is a list of channels. The channels have the description of the minimum
capacity and both participants. If the node happens to already have a channel
with the partner, and the capacity is equal-or-over the minimum amount, nothing
is done. If the channel exists and there is not sufficient balance, the script
will do a deposit. If the channel does not exist the script will open it.

The key `nodes` gives the local endpoint of *running* Raiden nodes, which the
script will use. Each key in `nodes` dictionary defines a name, these names are
then used as `node1` and `node2` to define the channel participants.

Note: Each of the running nodes must have test ETH on their accounts.
Note: For the deposit to work properly the nodes must have some of the required
tokens, for a test token one can use `mint.sh` to acquire some.

- `stress_test_transfers.py`: Script to run nodes and do some transfers. The
- script requires a configuration file, like so:

```ini
[DEFAULT]
keystore-path = ./keys
eth-rpc-endpoint = parity.goerli.ethnodes.brainbot.com:8545
network-id = goerli
token-address = 0xf9BA8aDF7F7024D7de8eB37b4c981CFFe3C88Ea7
pathfinding-service-address = https://pfs-goerli.services-dev.raiden.network 

[node1]
address = 0x5c11cc525590d9Ff8C7E4Af1704A39Df6c3884b5
password-file = ./keys/pass-UTC--2019-11-22T13-47-42.489814312Z--5c11cc525590d9ff8c7e4af1704a39df6c3884b5

[node2]
address = 0xa9FA88442c404716623155d150c526D8F1ae82E5
password-file = ./keys/pass-UTC--2019-11-22T13-49-45.745576867Z--a9fa88442c404716623155d150c526d8f1ae82e5

[node3]
address = 0x9df878E37C4B851bbe44841e72299F6f317C685C
password-file = ./keys/pass-UTC--2019-11-22T13-50-19.904075843Z--9df878e37c4b851bbe44841e72299f6f317c685c
```

This script does not take into account fees, therefore it must the no-fee PFS
(as per the example configuration above).

pylint
------

- `assert_checker.py`: Style tool that requires messages to all asserts.
- `gevent_checker.py`: Enforces some rules regarding gevent that are necessary
  for Raiden to work properly.
