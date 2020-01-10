# tools

- `parallel_tests.sh`: Tool to execute the test suite in parallel, useful to
  run multiple integration tests at the same time.
- `startcluster.py`: This tool will generate a genesis file with a few
  pre-funded accounts to be used as Raiden accounts, and then run a local
  Geth private chain, useful for debugging.
- `transfer_eth.py`: This is just a simple tool to send an eth transfer using
  the provided private key.

# debugging

## `stress_test_transfers.py`: run nodes and do some transfers
The script requires a configuration file. An example can be found at `tools/debugging/stress_test_transfers_config.ini`.

This script does not take into account fees, therefore it must use the no-fee PFS
(as per the example configuration above).

Before using the stress test for the first time, you need to prepare the three nodes given in the config file:
1. Create three accounts (e.g. with `geth account new`) and transfer some ETH to pay for the on-chain transactions.
2. Adapt `tools/debugging/stress_test_transfers_config.ini` and `tools/debugging/channels_with_minimum_balance_config.json` to your node configuration.
3. Uncomment the `input()` line in `stress_test_transfers.py` and start the script with the config file. Now the three nodes are running and you can use other scripts to interact with them.
4. Use `mint.sh` to mint tokens for the nodes (see section below).
5. Use `channel_with_minimum_balance.py` to create the channels and deposit tokens into the channels (see section below).
6. Now you can press enter to proceed past the `input` and start the stress test (or remove the `input()` line and start the script, again).

Going through these steps is cumbersome, but once you're done you can rerun the stress test any time without needing to repeat these steps. Only in case of failing stress tests, you might need to refill the channel balances with `channel_with_minimum_balance.py`.

## `mint.sh`: mint test tokens

Usage:
```sh
./mint.sh 0xf9BA8aDF7F7024D7de8eB37b4c981CFFe3C88Ea7 127.0.0.1:5001 127.0.0.1:5002 127.0.0.1:5000
```

The first argument is the test token with the `mintFor` function, the others
are endpoints of running Raiden nodes.

Note: Each of the running nodes must have test ETH on their accounts.

`mint.sh` requires [jq](https://stedolan.github.io/jq/), [httpie](https://httpie.org/) and [parallel](https://www.gnu.org/software/parallel/).

## `channels_with_minimum_balance.py`: open multiple channels and ensure deposit minimum

It needs a JSON file as shown in `tools/debugging/channels_with_minimum_balance_config.json`.

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

# pylint

- `assert_checker.py`: Style tool that requires messages to all asserts.
- `gevent_checker.py`: Enforces some rules regarding gevent that are necessary
  for Raiden to work properly.
