## Scenarios

The scenarios listed within this folder are getting executed nightly by the [scenario player](https://github.com/raiden-network/scenario-player/) or can be executed locally after installing the scenario player.

## Purpose

The scenarios serve the following purpose

- Full end-to-end tests covering contracts, transport, Raiden client, blockchain, eth-client, monitoring service, pathfinding service and service contracts
- Testing on a "dirty" blockchain
- User acceptance tests
- Testing in a distributed environment
- Understanding how Raiden and the Raiden Services can be used and interact

## Writing scenarios

If you want to write a new scenario you can check out the [following example file](https://github.com/raiden-network/scenario-player/blob/master/examples/scenario-example-v2.yaml).

## Scenarios

#### [bf1_basic_functionality](./bf1_basic_functionality.yaml)

It creates a network with topology 0 <-> 1 <-> 2 <-> 3 <-> 4. From here the basic functionality of channels are tested.
Payments without and with enough capacity are made. Several payments from different initiators and receivers are made.
Checks to verify that the PFS works as intended take place. The partial withdraw and deposit functionality is tested.
It is also tested that a node can be stopped and started again and that it still functions as expected after this.
Several nodes perform up to 100 payments.
In the end it is tested that channels can be closed and that the monitoring service correctly kicks in if a node is offline during closing.

#### [bf2_long_running](./bf2_long_running.yaml)

This scenario mimics user behaviour for
opening channels, depositing, transferring, waiting keeping the raiden node alive for
a long time in the process checking that the raiden network
works accurately with a sufficiently dirty state of blockchain for a long time.

#### [bf3_multi_directional_payment](./bf3_multi_directional_payment.yaml)
It sets up a topology of [0, 1, 2, 3, 4] and deposits in both directions between all nodes.
When all channels are opened and deposits have taken place, 100 payments are started from node0 to node4
At the same time 100 payments are done in parallel from node4 to node0.
After all payments have finished it is asserted that all nodes received the correct amounts.

#### [bf4_multi_payments_same_node](./bf4_multi_payments_same_node.yaml)
It sets up a topology of [0, 1, 2, 3, 4] and deposits in both directions between all nodes.
When all channels are opened and deposits have taken place, 100 payments are started from node0 to node4
At the same time 100 payments are done in parallel from node4 to node0.
After all payments have finished it is asserted that all nodes received the correct amounts.

#### [bf5_join_and_leave](./bf5_join_and_leave.yaml)
It sets up a simple topology of two nodes and then uses
`join_network` to add more nodes to the network. It tests that nodes can join the network
with nodes that didn't use `join_network` themselves and that nodes that used `join_network`
also deposits in new channels when other nodes open channels with them. Finally it also
tests that nodes using `leave_network` have all their open channels closed, when doing so.

#### [bf6_stress_hub_node](./bf6_stress_hub_node.yaml)
It sets up a tolopogy with 9 nodes connected to node0,
so that node0 is the single hub that all payments have to go through. First one
payment from each node to another node is carried out in parallel, to check that
the hub can handle this amount of load. Then 5 payments from each node to another
node is carried out in order to check that node0 can handle this load.

#### [bf7_long_path](./bf7_long_path.yaml)
It tests long paths. There are a total of 15 nodes in the scenario.
A topology with deposits in both directions are created as [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
After opening channels, transfers are made with incrementing length starting with a transfer
from node0 to node1 and back, then from node0 to node2 with node1 as a mediatorand back etc.
This is done all the way up to a transfer from node0 to node14 and back.

#### [ms1_simple_monitoring](./ms1_simple_monitoring.yaml)

A channel between two nodes is opened, a transfer is made. Then, node1 goes offline
and node0 closes the channel. The asserts checks whether the monitoring service interferes and received its reward.

#### [ms2_simple_monitoring](./ms2_simple_monitoring.yaml)

A channel between two nodes is opened, a transfer is made. Then, node1 goes offline and node0 closes the channel. Node1 does not get back online in time and cannot update the channel info by herself. The monitoring services interferes and gets its reward. After the monitoring trigger block is passed node1 gets back online.

#### [ms3_simple_monitoring](./ms3_simple_monitoring.yaml)

A channel between two nodes is opened, a transfer is made. Then, node1 goes offline and node0 closes the channel. Before the monitoring trigger block is passed node1 gets back online. Node1 calls the smart contract itself and therefore the MS does not get triggered.

#### [ms4_udc_too_low](./ms4_udc_too_low.yaml)

This scenario tests that the MS does not kick in, if the node requesting monitoring does
not have enough funds deposited in the UDC. A channel is opened between node0 and node1.
A couple of transfers take place and node1 then goes offline. Node0 calls close and node1
stays offline. It is then expected that the MS does not kick in, since node1 does not have
enough tokens deposited.

#### [pfs1_get_a_simple_path](./pfs1_get_a_simple_path.yaml)

It creates a network with topology 0 <-> 1 <-> 2 <-> 3 and checks whether a path is returned.

#### [pfs2_simple_no_path](./pfs2_simple_no_path.yaml)

It creates a network with topology 0 -> 1 -> 2 -> 3 and checks that no path is returned since there is no capacity in the direction from 3 to 0.

#### [pfs3_multiple_paths](./pfs3_multiple_paths.yaml)

It creates a network with topology 0 <-> 1 <-> 2 <-> 3 and 0 <-> 4 <-> 3 and checks whether two paths are returned.

#### [pfs4_use_best_path](./pfs4_use_best_path.yaml)

It creates a network with topology 0 <-> 1 <-> 2 <-> 3 and 0 <-> 4 <-> 2 and checks whether the best path is the one used for the payment.
Note that `max-paths` is set to 1 path.

#### [pfs5_too_low_capacity](./pfs5_too_low_capacity.yaml)

It creates a network with topology 0 <-> 1 <-> 2 <-> 3 and 0 <-> 4 <-> 3, where 0 <-> 4 <-> 3 doesn't have enough capacity to make a second transfer after one transfer is made and hence the other path is used for that transfer. This also checks that the PFS reacts correctly to the capacity update.
Note that `max-paths` is set to 1 path.

#### [pfs6_simple_path_rewards](./pfs6_simple_path_rewards.yaml)

It creates a network with topology 0 <-> 1 <-> 2 <-> 3 and performs some transfers in order to check that IOUs are created for the PFS that provides the path.

#### [pfs7_multiple_payments](./pfs7_multiple_payments.yaml)

This scenario sets up a topology of [0, 1, 2, 3] and [0, 4, 3] with deposits in both directions.
100 payments is then carried out and assertions are made to ensure the PFS gets the corrects amount
of requests and IOUs. During the transfers the [0, 4, 3] path will have too low capacity and the other one
should be used.

#### [pfs8_mediator_goes_offline](./pfs8_mediator_goes_offline.yaml)

This scenario aims to make sure that the PFS reacts correctly if a node along
a path goes offline and thus provides a new path is one is available.
A topology of 0 <-> 1 <-> 2 <-> 3 and 0 <-> 4 <-> 3 will be used.
Node0 will first make a payment to node3 through [0, 4, 3] and then node4 goes offline. It is
then expected that the path [0, 1, 2, 3] is used instead.

#### [pfs9_partial_withdraw](./pfs9_partial_withdraw.yaml)
This scenario aims to make sure that the PFS reacts correctly to balance updates
after a partial withdraw takes place.
A topology of 0 <-> 1 <-> 2 <-> 3 and 0 <-> 4 <-> 3 will be used.
Node0 will first make a payment to node3 through [0, 4, 3] and then node4 makes a partial withdraw
results in not enough capacity for a second transfer to be routes through that path.
The expected path for the second transfer is then [0, 1, 2, 3].

#### [mfee1_flat_fee](./mfee1_flat_fee.yaml)
This scenario creates a network with topology 0 -> 1 -> 2 -> 3 and only enables flat mediation fees.
It then checks whether a path is returned. It also checks that correct flat mediation fees are deducted.

#### [mfee2_proportional_fees](./mfee2_proportional_fees.yaml)
The MFEE2 scenario creates a network with topology 0 -> 1 -> 2 -> 3 and checks
whether a path is returned. It also checks that correct proportional mediation fees are deducted
and received by the mediating parties. For every 1000 TKNs tranferred a fee of 10 TKN is expected.

#### [mfee3_only_imbalance_fees](./mfee3_only_imbalance_fees.yaml)
Make a transfer over a single mediator with enabled imbalance fees. The
channels start at maximum imbalance, which causes negative fees. To test this,
the mediator fee capping has been turned off.

#### [mfee4_combined_fees](./mfee4_combined_fees.yaml)
This scenario creates a network with topology 0 -> 1 -> 2 -> 3 and only enables all mediation fee components.
It then checks whether a path is returned. It also checks that correct mediation fees are deducted.
