Raiden Developer Onboarding Guide
#################################
.. toctree::
  :maxdepth: 2

Introduction
============
This is a general onboarding guide whose main purpose is to help people who want to develop Raiden. It provides an in-depth explanation of the protocol followed by an explanation of the architecture.

For information on coding style, commit rules and other development rules please refer to the `Contributing Guide <https://github.com/raiden-network/raiden/blob/master/CONTRIBUTING.md>`_.

The Raiden Protocol
===================

In this section we will have the general explanation of how the Raiden protocol works, starting from the smart contracts and ending with the offchain messages that are exchanged between Raiden nodes.
For a more formal definition of the protocol please refer to the `specification <https://raiden-network-specification.readthedocs.io/en/latest/>`_.

Smart contracts
***************

Raiden has 4 smart contracts that are needed to support the protocol. They can all be found at the `smart contracts repository <https://github.com/raiden-network/raiden-contracts>`_. The repository also contains scripts to deploy and verify the contracts on different networks.

Token Network Registry
~~~~~~~~~~~~~~~~~~~~~~

The `Token Network Registry <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetworkRegistry.sol>`_ contract is the main component that defines a deployment of the Raiden Network.

It is a registry of all different TokenNetwork contracts, one for each token. When someone wants to register a Token and create a network for it they interact with the TokenNetworkRegistry's `createERC20TokenNetwork() <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetworkRegistry.sol#L59>`_ function.

Token Network
~~~~~~~~~~~~~

Once a token has been registered with the registry a new `Token Network <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol>`_ is created for that Token. This is the main contract with which to interact for all onchain channel operations for that token.

Secret Registry
~~~~~~~~~~~~~~~

The `Secret Registry <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/SecretRegistry.sol>`_ is a contract that is deployed along with the ``TokenNetworkRegistry`` and together they define a deployment of the protocol.

It is used when a user needs to `register <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/SecretRegistry.sol#L20>`_ a secret onchain to prove that they knew the secret for a pending transfer before the block of the lock expiration has come.

Endpoint Registry
~~~~~~~~~~~~~~~~~

The `Endpoint Registry <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/EndpointRegistry.sol>`_ contract is a contract used only by the now deprecated `UDP transport <https://github.com/raiden-network/raiden/tree/3ae9ecccdf5d48fd5a9a07fae4752d4971cf6868/raiden/network/transport/udp>`_.

It serves as a mapping between user's ethereum addresses and ip addresses so that the transport layer knows where to send messages to.


Channel Opening Lifecycle
*************************

.. figure:: images/channel_open_deposit.png
    :width: 600px

    The channel opening lifecycle

A channel between two participants can be `opened <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L253>`_ by anyone. But there can be only one channel open between two participants at any time.

Once the channel is open then, anyone can `deposit <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L307>`_ an amount of tokens for either of the two participants. Depositing is done via idempotent calls. That's why the function is called ``setTotalDeposit``, so that if it's called multiple times the result is always going to be the same. The function does not deposit a new amount each time but instead alters the amount of the total deposit that should be in the contract for a participant.


At this point the channel is active and payments can be made.

.. note::
   The withdraw functionality of the contract is currently disabled

At any point and if both participants agree they can also `withdraw <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L375>`_ tokens from the contract via an onchain transaction.


.. _offchain-messages:

Messages Exchanged during a Raiden Transfer
*******************************************

.. _happy-case-transfer-messages:

The Happy Case
~~~~~~~~~~~~~~

.. figure:: images/transfer_happy_case.gif
    :width: 600px

    Happy case of a Raiden Transfer

Let's first look at the messages exchanged in the happy path of a Raiden Transfer. Each Transfer has an ``Initiator``, a ``Target`` and zero or more ``Mediators``. The ``Initiator`` creates a `Locked Transfer <https://github.com/raiden-network/raiden/blob/38971b372dafb3205cbd3df8cfc3306922a55eac/raiden/messages.py#L1124>`_ message and propagates it to the ``Target`` through multiple Mediators.

Once the ``LockedTransfer`` reaches the ``Target`` then they requests the secret from the ``Initiator`` by sending a `Secret Request <https://github.com/raiden-network/raiden/blob/38971b372dafb3205cbd3df8cfc3306922a55eac/raiden/messages.py#L468>`_ message.

When the ``Initiator`` gets the secret request message, they check to make sure that it's a valid one and that it corresponds to a locked transfer that they sent out. If all checks out they send a `Reveal Secret <https://github.com/raiden-network/raiden/blob/38971b372dafb3205cbd3df8cfc3306922a55eac/raiden/messages.py#L710>`_ message back to the ``Target``.

The ``Target`` will process the secret message, register it into their state and then proceed to reveal the secret backwards by sending their own ``RevealSecret`` message to their counterparty.

The counterparty which can either be a ``Mediator`` or the ``Initiator`` will receive this ``RevealSecret`` message and process it. This message tells them that the payee (either the target or another mediator if we got multiple hops) knows the secret and wants to claim the lock off-chain. So then they may unlock the lock and send an up-to date balance proof to the payee. This is done by sending what we (unfortunately) call the `Secret <https://github.com/raiden-network/raiden/blob/38971b372dafb3205cbd3df8cfc3306922a55eac/raiden/messages.py#L557>`_ message back to the partner who sent the ``Reveal Secret``.

This concludes the transfer for that hop. If the receiver of ``RevealSecret`` was the ``Initiator`` then the transfer is finished end-to-end. If it was just a ``Mediator`` then they will have to propagate the transfer backwards by sending a ``RevealSecret`` message backwards to their partner repeating the procedure outlined above.


An Unhappy Case
~~~~~~~~~~~~~~~

.. figure:: images/transfer_unhappy_case.gif
    :width: 600px

    Unhappy case of a Raiden Transfer

Looking at a similar network topology as shown in the happy case above, let's see how the protocol behaves when something goes wrong and our partner does not follow the protocol.

As seen in the figure above once the payee sends the ``Reveal Secret`` message the payer does not respond with the expected balance proof message. If that happens the payee has two choices:

1. If the amount involved in the token is really small then the payee can just do nothing and forfeit it.
2. If the amount is worth an on-chain transaction then the payee can go on-chain by registering the secret on the ``SecretRegistry`` contract and prove he knew the secret before the block of the lock expiration. From that point on the protocol can continue as before but now the secret is visible onchain so everyone along the path now knows it.


Offchain messages at Lock Expiration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If for some reason the protocol does not proceed and the Target never requests for the secret then the pending transfer lock will at some point expire. At the point of expiration in a payer-payee channel the payer will have to notify the payee that the lock has expired by sending a `LockExpired <https://github.com/raiden-network/raiden/blob/38971b372dafb3205cbd3df8cfc3306922a55eac/raiden/messages.py#L1452>`_ message.

The payee receives the ``LockExpired`` message, removes the lock from its pending locks for the partner and updates the state with tne new balance proof.



Routing
*******

.. figure:: images/routing_a_transfer.gif
    :width: 600px

    Routing a Transfer

At the moment routing in Raiden works in a very simple manner. Each node has a global view of the network knowing the initial capacity of each channel by watching for the deposit events happening on chain. As a result each node keeps a graph of the network but that graph may be outdated due to the capacity changing because of offchain transfers.

Each node tries to forward the transfer through the shortest path with enough capacity to the target. If at some poin the transfer can't go through due to the actual capacity not being sufficient or due to the node being offline then a special kind of LockedTransfer called a `Refund Transfer <https://github.com/raiden-network/raiden/blob/38971b372dafb3205cbd3df8cfc3306922a55eac/raiden/messages.py#L1344>`_ will be sent back to the payer, effectively refunding him the transferred amount and allowing him to try another route. This is repeated until either a route is found or we have no other ways to reach the target at which case the Transfer fails.

If the transfer reaches the target and the protocol is followed properly as we saw in the :ref:`happy transfer case <happy-case-transfer-messages>` above then all the pending transfers in the path will be unlocked and the node balances will be updated.

.. _pending-transfers-mediator:

Pending Transfers
******************

.. figure:: images/pending_transfers_for_mediator.gif
    :width: 600px

    Pending transfers from the perspective of a mediator

When a node mediates transfers all of the locks are kept on the state of the mediator node inside a merkle tree. For each new transfer the lock is appended to the merkle tree.

If the protocol is followed as shown in the :ref:`happy transfer case <happy-case-transfer-messages>` above then the corresponding lock is unlocked and removed from the merkle tree.

.. _close_settlement_lifecycle:

Close/Settlement Lifecycle
**************************

.. figure:: images/channel_close_settle.png
    :width: 600px

    Channel close/settle lifecycle


At some point in a channel's life either of the participants will want to close the channel. This can happen in one of two ways.

1. If both participants agree on the final state of the channel offchain then they can utilitize the `cooperative settle <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L860>`_ method to close the channel with only 1 onchain transaction.

2. If on the other hand the nodes don't agree offchain (a common adversarial scenario) then one participant needs to first `close <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L470>`_ the channel with the state of received transfers from their partner. Then the partner will have to `update <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L536>`_ the contract with their side of received transfers.

All of the above can also be sent to the chain by a third party.

Once either a cooperative or a normal close is done and the settlement period has passed then anyone can invoke the `settle <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L623>`_ function in the contract to payout the tokens owed to either participant from the finalized transfers.

Finally once the channel is settled, each participant that may have pending offchain transfers that were not finalized can at this point try to `unlock <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L762>`_ them onchain.


Unlocking Pending Transfers
***************************

At this section we are going to look in more detail how the unlocking of pending transfers mentioned in the previous section works.

.. figure:: images/settle_pending_locks.gif
    :width: 600px

    Unlocking pending transfers onchain after settlement

Continuing from the example seen in the :ref:`pending transfers <pending-transfers-mediator>` section above let's explore what happens when ``B``'s partner closes the channel while there are transfers pending.


In the figure above the following things happen:

1. For the payment A->B->C , ``C`` follows the protocol and send the secret back to ``B``.
2. At the same time ``A`` closes the channel and so the normal offchain protocol can not be followed. Instead we enter the channel :ref:`close/settlement <close_settlement_lifecycle>` lifecycle we saw in the previous section with ``A`` closing the channel with what he received from his partner ``B``.
3. Now ``B`` has to register the secret received by ``C`` onchain as he can no longer do it offchain. He has to prove that he knew the secret at a block height before the pending transfer's expiration. He does that by calling `registerSecret <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/SecretRegistry.sol#L20>`_ on the ``SecretRegistry`` contract.
4. Now it's ``B``'s turn to update the contract with what he has received from ``A``. He will provide a hash of the merkle root, the transferred amount and the locked amount to the contract via the `updateNonclosingbalanceproof <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L536>`_ call.
5. After both are done and the settlement period has passed then anyone can settle the channel and send the tokens amounts owed to ``A`` and ``B`` respectively back to its owners.
6. After settlement whoever has pending transfers that need to be unlocked on chain has to unlock them onchain. In this example ``B`` will provide the merkle tree to the contract via the `unlock <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L762>`_ function. That will result in the contract checking each one of the locks and send the locked tokens for which the secret was registered on time to the intended receiver (``B``) and those for which it wasn't back to the payer (``A``).



Raiden Architecture
===================

In this section we are going to see an explanation of how the code of the Raiden client is structured and how it implements the protocol detailed in the previous section and.


Architecture Overview
*********************

.. figure:: images/architecture_overview.png
    :width: 600px

    Raiden Architecture Overview


At the core of the Raiden architecture lies a state machine. The state machine gets fed state changes from various sources such as:

- User commands directly from the user through the REST API
- Trigerred via blockchain via polling for blockchain events
- Triggered by receiving an offchain message

All these state changes are processed along with the current state and produce a new state along with something that we call the "Raiden Internal Events" which is essentially I/O since the state machine can't do I/O on its own.

Processing those raiden internal events performs all kinds of I/O such as:

- Sending offchain messages
- Sending onchain transactions
- Logging a debug message

The State Machine
*****************

The entire state machine code is located under the `transfer <https://github.com/raiden-network/raiden/tree/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer>`_ directory. For a good overview of all the classes used in the state machine check the `architecture <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/architecture.py>`_ file.

The `StateManager <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/architecture.py#L195>`_ class is where the application state is stored. Also at the `dispatch() <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/architecture.py#L217>`_ function is where the state changes are applied to the current state through the state transition function and produce the next state and a list of Raiden Internal events.

The result of the application of a state change is represented by the `TransitionResult <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/architecture.py#L263>`_ class. It is essentially a tuple containing the new state and a list of Raiden internal events produced by the state transition.

.. figure:: images/state_tasks.png
    :width: 600px

    State tasks hierarchy

The state in Raiden is kept in a hierarchical manner in what we call "Tasks". At the top is the node state represented by the `ChainState <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/state.py#L229>`_ class. Whenever a node starts up the first state change we get is the `ActionInitChain <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/state_change.py#L345>`_ state change and through its application we get the aforementioned ``Chain State``. All state changes first pass through this level via the `node state transition function <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/node.py#L1161>`_.

When we start we also create a new `PaymentNetwork <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/state.py#L348>`_ state corresponding to the default Token Network Registry contract. In the future there could be multiple token network registries but at the moment we only register the default.

Whenever we get a blockchain event denoting that a new Token Network was created then an `ActionNewTokenNetwork <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/state_change.py#L402>`_  state change is created. `Processing <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/node.py#L548>`_ that state change a `TokenNetworkState <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/state.py#L409>`_ is added to the ``PaymentNetworkState``. All state changes that need to go down to the TokenNetwork are eventually `subdispatched <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/node.py#L475>`_ from the node state to the Token Network's `state transition <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/token_network.py#L338>`_ function.

Whenever we `receive <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/blockchain_events_handler.py#L89>`_ a blockchain event denoting that a new channel was opened and we are a participant a `ContractReceiveChannelNew <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/state_change.py#L232>`_ state change containing the channel's `NettingChannelState <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/state.py#L1403>`_ is generated sent into the state machine. It's processed and added into the corresponding ``TokenNetworkState``. From this point on all state changes that concern a specific channel are subdispatched from the TokenNetwork processing to the channel's `state transition <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/channel.py#L2085>`_ function.

All the state related to mediated transfers is kept under the `transfer/mediated_transfer <https://github.com/raiden-network/raiden/tree/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer>`_ directory.

If our node initiates a transfer then it takes on the role of the Initiator and an `ActionInitInitiator <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/state_change.py#L19>`_ state change is generated. Then it's `subdispatched <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/node.py#L210>`_ to the initiator manager's `state transition <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/initiator_manager.py#L285>`_ where a new `InitiatorPaymentState <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/state.py#L39>`_ task will be created. From now on all state changes that affect this transfer will be subdispatched to this Initiator task.

If our node mediated a transfer then it takes on the role of the mediator and an `ActionInitMediator <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/state_change.py#L68>`_ state change is generated. Then it's `subdispatched <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/node.py#L261>`_ to the mediator's `state transition <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/mediator.py#L1298>`_ function where a new `MediatorTransferState <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/state.py#L198>`_ task will be created. From now on all state changes that affect this transfer will be subdispatched to this Mediator Task.

Finally if our node receives a transfer whose intended recipient is the node itself then it takes on the role of the target and an `ActionInitTarget <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/state_change.py#L133>`_ state change is generated. Then it's `subdispatched <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/node.py#L312>`_ to the target's `state transition <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/target.py#L294>`_ function where a new `TargetTransferState <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/mediated_transfer/state.py#L264>`_ task will be created. From now on all state changes that affect this transfer will be subdispatched to this Target Task.

.. _raiden-internal-events:

Raiden Internal Events
**********************

As mentioned before all state transitions may generate a list of `Raiden Events <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/architecture.py#L83>`_.

Since the state machine itself can have no side effects or I/O these events act as a trigger for all side effects. After a state change has been `processed <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_service.py#L462>`_ we get the event list. `For each <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_service.py#L467>`_ of these events we `invoke <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_service.py#L475>`_ the `RaidenEventHandler <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_event_handler.py#L69>`_ which will process the events and trigger the appropriate side effects.

For example `send a locked transfer <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_event_handler.py#L132>`_ or `settle a channel <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_event_handler.py#L414>`_ if the settlement period has ended.


The Write Ahead Log
*******************

.. figure:: images/write_state_change_to_wal.png
    :width: 600px

    Logging a state change to the WAL before dispatching to the state machine

Before a state change is dispatched to the state machine for processing we `write <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/storage/wal.py#L49>`_ it into a Database called the Write Ahead Log. This allows Raiden to be persistent in case of crashes or other forms of irregular shutdown.

All that is needed in order to recreate the latest state is the initial state and the sum of state changes that lead up to it. So during a restart we `read <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_service.py#L285>`_ all the state changes in the WAL and replay them to recreate the latest state.

.. figure:: images/restore_wal.png
    :width: 600px

    Restoring the state from the WAL

If Raiden has been running for many days then a lot of state changes will have gathered. Replaying all of these state changes at restart would take a lot of time so as an optimization at regular internals we are taking a `snapshot <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_service.py#L500>`_ of the current state. Subsequently at restart we restore the snapshotted state, retrieve the state changes since the snapshots and replay only those state changes to get to the final state.

The Transport Layer
*******************

The Raiden Transport layer is responsible for the receiving and sending of the off-chain messages. The current architecture allows for a pluggable transport layer through the use of a common transport interface. We have two implementation of this interface. The deprecated `UDPTransport <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/transport/udp/udp_transport.py#L155>`_ and the `MatrixTransport <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/transport/matrix.py#L262>`_.

Irrespective of the transport layer once a message is received it will eventually be forwarded to the `MessageHandler <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/message_handler.py#L41>`_ which will generate the proper state changes and dispatch them to the state machine described in the previous section.

The Matrix Transport
~~~~~~~~~~~~~~~~~~~~

The reasoning behing the choice of Matrix as a transport layer for Raiden is nicely explaing in `this <https://medium.com/raiden-network/raiden-transport-explained-939d7741b6f4>`_ blogpost.

In this section we are going to only look over the main points in the code which are the entries to the transport layer. For more information please check out the matrix transport `spec <https://raiden-network-specification.readthedocs.io/en/latest/transport.html>`_.

In Matrix each user has a userid in the form of ``@<userId>:<homeserver_uri>``. ``userId`` is the lowercased ethereum address of the node, possibly followed by a 4-bytes hex-encoded random suffix, separated from the address by a dot. The ``homeserver_uri`` is the URI of the matrix homeserver at which the user registers.

For each partner we interact with a specific room is created on the matrix home server between us and our partner. The `_handle_message() <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/transport/matrix.py#L727>`_ function is the entry point to any messages received in such a room and after some validation it is forwarded to `_receive_message() <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/transport/matrix.py#L896>`_ which will finally forward to the message handler.

As for sending messages to a partner in a channel the `send_async() <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/transport/matrix.py#L458>`_ function is the entry point. It essentially populates the sending queue for the partner. The actual messages will be sent from the queue during the main loop of the transport through the `_check_and_send() <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/transport/matrix.py#L182>`_ function.

Messages acknowledgment and processing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All the messages seen in the :ref:`offchain messages <offchain-messages>` section need to be (1) seen and (2) succesfully processed by the partner node. To facilitate synchronization of that fact the transport layer makes sure that all messages but ``Delivered`` itself cause a ``Delivered`` to be sent.

The `Delivered <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/messages.py#L380>`_  message is sent right when the transport receives a message and before processing. It just tells the sender that the message was received and will be processed.

For some messages (aka the messages in the “global” queue), it’s enough for them to be removed/cleaned from the queue, triggering the transport to stop retrying sending them. For the ones in the specific queues, they’ll wait for the `Processed <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/messages.py#L328>`_ message, informing not only that the message was delivered, but also that the processing of the respective state change occurred successfully, or else keep retrying.

So, for a specific queue message, e.g. a ``LockedTransfer`` in a specific channel:

- -> A sends a ``LockedTransfer`` and starts a retry loop for it with message_id=123
- <- B receives it and sends ``Delivered(123)``.
- <- B accepts it (i.e. succesfully processes it). Then sends ``Processed(123)`` and starts a retry loop for it.
- -> A receives ``Delivered(123)``. Stops retry loop for any message_id=123 from B in its general queue, which is none, so it effectivelly skips it.
- -> A receives ``Processed(123)``, stops retry loop for any message_id=123 from B in its specific queue (in this case, ``LockedTransfer``), sends ``Delivered(123)`` in reply to ``Processed(123)``.
- <- B receives ``Delivered(123)``, stops retry loop for any message_id=123 from A in its global queue (in this case, ``Processed``).

Blockchain Communication
************************

We communicate with the blockchain through the `JSONRPCClient <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/rpc/client.py#L246>`_ class. That class is a wrapper of ``web3.py`` for all blockchain JSON RPC calls and also checks that the underlying ethereum client is compatible with Raiden. Checks things such as that all required interfaces are enabled and that the version is high enough (Byzantium enabled).

We communicate with each smart contract through the notion of a smart contract `proxy <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/rpc/smartcontract_proxy.py#L59>`_. Each proxy is a essentially a class exposing the functionality of a specific contract using the ``JSONRPCClient``.

We have proxies for all the contracts:

- `EndpointRegistry <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/proxies/discovery.py#L20>`_
- `TokenNetworkRegistry <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/proxies/token_network_registry.py#L30>`_
- `TokenNetwork <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/proxies/token_network.py#L78>`_
- `SecretRegistry <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/proxies/secret_registry.py#L19>`_
- `PaymentChannel <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/network/proxies/payment_channel.py#L16>`_ - This is just a wrapper of the token network functions for a specific channel.


Processing onchain events
~~~~~~~~~~~~~~~~~~~~~~~~~

All the events that happen onchain are `polled <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/blockchain/events.py#L226>`_ after a new block is `received <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/raiden_service.py#L544>`_ and all found events are forwarded to the `blockchain event handler <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/blockchain_events_handler.py#L295>`_.

From there each different event is processed and appropriate state changes are generated and dispatched to the state machine to be processed by it as we saw before.

Sending onchain transactions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As mentioned before a byproduct of state transitions in the state machine are Raiden Internal `events <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/architecture.py#L83>`_. A certain subset of those events, the `ContractSendEvent <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/transfer/architecture.py#L151>`_ is what allows us to send on chain transactions.

As seen in the :ref:`Raiden Internal Events <raiden-internal-events>` section if a `ContractSendXXX` event is sent to the ``RaidenEventHandler`` then it will be processed and eventually the appropriate proxy will generate an onchain transaction.


The Rest API
************

All Raiden user facing actions are exposed via a REST API. For a full documentation of the endpoints check the :doc:`REST API documentation <rest_api>`.

As far as the code is concerned all of the functionality to interact with Raiden is inside what we call the `Python API <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/api/python.py#L83>`_. The ``RaidenAPI`` class has all the functions which deal with channel operations, transfers e.t.c.

These functions are exposed to the user through the REST API `endpoints <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/api/rest.py#L101>`_ of the `RestAPI <https://github.com/raiden-network/raiden/blob/761bedfee2ee326401ad5ec95d55b1ab458a5213/raiden/api/rest.py#L488>`_ class.

The WebUI
=========

Raiden has a graphical user interface. It's an angular application running by default along with the raiden node and exposing an interface that can be accessed via the user's Browser

TODO: Small overview of code architecture for the WebUI.
