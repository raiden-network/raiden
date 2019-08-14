## Scenarios

The scenarios listed within this folder are getting executed nightly by the [scenario player](https://github.com/raiden-network/scenario-player/) or can be executed locally after installing the scenario player.

## Purpose

The scenarios serve the following purpose

- Full end-to-end tests covering contracts, transport, Raiden client, blockchain, eth-client, monitoring service, pathfinding service and service contracts
- Testing on a "dirty" blockchain
- User acceptance tests
- Testing in a distributed environment
- Understanding how Raiden and the Raiden Services can be used and interact

## Scenarios

#### [ms1_simple_monitoring](./ms1_simple_monitoring.yaml)

A channel between two nodes is opened, a transfer is made. Then, node 1 goes offline and node 0 closes the channel. The last assert checks whether the monitoring service interferes and received its reward.

#### [ms2_simple_monitoring](./ms2_simple_monitoring.yaml)

A channel between two nodes is opened, a transfer is made. Then, node 1 goes offline and node 0 closes the channel. node 1 does not get back online in time and cannot update the channel info by herself. The monitoring services interferes and gets its reward. After the monitoring trigger block is passed node 1 gets back online.

#### [ms3_simple_monitoring](./ms3_simple_monitoring.yaml)

A channel between two nodes is opened, a transfer is made. Then, node 1 goes offline and node 0 closes the channel. Before the monitoring trigger block is passed node 1 gets back online. Node 1 calls the smart contract itself and therefore the MS does not get triggered.

#### [pfs1_get_a_simple_path](./pfs1_get_a_simple_path.yaml)

It creates a network with topology A <-> B <-> C <-> D and checks whether a path is returned.

#### [pfs2_simple_no_path](./pfs2_simple_no_path.yaml)

This is the PFS1 scenario. It creates a network with topology A <-> B <-> C <-> D and checks whether a path is returned.

#### [pfs3_multiple_paths](./pfs3_multiple_paths.yaml)

It creates a network with topology A <-> B <-> C <-> D and A <-> E <-> D and checks whether two paths are returned.

#### [pfs4_use_best_path](./pfs4_use_best_path.yaml)

It creates a network with topology A <-> B <-> C <-> D and A <-> E <-> D and checks whether the best path is the one used for the payment.

#### [pfs5_too_low_capacity](./pfs5_too_low_capacity.yaml)

It creates a network with topology A <-> B <-> C <-> D and A <-> E <-> D where the path AED doesn't have enough capacity to do the transfer.

#### [pfs6_low_capacity](./pfs6_low_capacity.yaml)

It creates a network with topology A <-> B <-> C <-> D and A <-> E <-> D where the path AED has low, but enough capacity to do the transfer.

#### [pfs7_simple_path_rewards](./pfs7_simple_path_rewards.yaml)

It creates a network with topology A <-> B <-> C <-> D and performs some transfers in order to check that IOUs are created for the PFS that provides the path.
