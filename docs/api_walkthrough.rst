Getting started with the Raiden API
###################################


Contents:

.. toctree::
   :maxdepth: 2



Introduction
*************
Raiden has a Restful API with URL endpoints corresponding to actions that the user can perform with his channels. The endpoints accept and return JSON encoded objects. The api url path always contains the api version in order to differentiate queries to different API versions. All queries start with: ``/api/<version>/`` where ``<version>`` is an integer representing the current API version.

In this guide we will walk through the steps necessary in order to participate in a Raiden Token Network. We will provide some different scenarios such as joining an already existing token network, registering a new token network, together with opening, closing and settling channels.

Before you get started with below guides, please see :doc:`Overview and Guide <Overview-And-Guide>`, to make sure that you are connected to Raiden.

Furthermore, to see all available endpoints, please see :doc:`REST API Endpoints <Rest-Api>`.


Scenarios
*********
Below you'll find a series of different scenarios showing different ways that the Raiden API can be used and interacted with.

A good way to check that you started Raiden correctly before proceeding is to check that your Raiden address is the same address as the Ethereum address that you chose, when starting the Raiden node::

    GET /api/1/address

If this returns your address, you know that your Raiden node has the API up and running.

.. _bootstrapping-a-token-network:

Bootstrapping a token network
=============================
In this scenario we assume that a user holds some ERC20 tokens of a type that has not yet been registered in the Raiden smart contracts. Let's assume that the address of the token is ``0x9aBa529db3FF2D8409A1da4C9eB148879b046700``.

The user wants to register the token, which will create a `Channel Manager <https://github.com/raiden-network/raiden/blob/a64c03c5faff01c9bd6aab9bd357ba44c113129e/raiden/smart_contracts/ChannelManagerContract.sol>`_. For each registered token there is a channel manager. Channel managers are responsible of opening new payment channels between two parties.


Checking if a token is already registered
-----------------------------------------
One way of checking if a token is already registered is to get the list of all registered tokens and check if the address of the token you want to interact with exists in the list::

    GET /api/1/tokens

If the address of the token you want to interact with exists in the list, see the :ref:`next scenario <joining-existing-token-network>`.
If it does not exist in the list, we need to :ref:`register the token <adding-a-token>`.


.. _adding-a-token:

Registering a token
-------------------
In order to register a token all we need is its address. When a new token is registered a Channel Manager contract is deployed, which makes it quite an expensive thing to do in terms of gas usage ``TODO insert estimated gas price``.

To register a token simply use the endpoint listed below::

    PUT /api/1/tokens/0x9aBa529db3FF2D8409A1da4C9eB148879b046700

If successful this call will return the address of the freshly created Channel Manager like this::

    {"channel_manager_address": "0xC4F8393fb7971E8B299bC1b302F85BfFB3a1275a"}

The token is now registered. However, since we're the ones registering the token, there will be nobody else to connect to right away. This means that we need to bootstrap the network for this specific token. If we know of some other Raiden node that holds some of the tokens we just added or we simply want to transfer some tokens to another Raiden node in a one way channel, we can do this quite easily by simply opening a channel with this node. The way we open a channel with another Raiden node is the same whether the partner already holds some tokens or not.


.. _opening-a-channel:

Opening a channel
-----------------
To open a channel with another Raiden node we need four things: the address of the token, the address of the partner node, the amount of tokens we want to deposit, and the settlement timeout period. With these things ready we can open a channel::

    PUT /api/1/channels

With the payload::

    {
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
        "balance": 1337,
        "settle_timeout": 600
    }

* TODO adjust settle_timeout ?

At this point we don't worry too much about the `"balance"` field, since we can always :ref:`deposit more tokens <depositing-to-a-channel>` to a channel if need be.

Successfully opening a channel will return the following information::

    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
        "balance": 1337,
        "state": "open",
        "settle_timeout": 600
    }

Here it's interesting to notice that a `"channel_address"` has been generated. This means that a `Netting Channel contract <https://github.com/raiden-network/raiden/blob/a64c03c5faff01c9bd6aab9bd357ba44c113129e/raiden/smart_contracts/NettingChannelContract.sol>`_ has been deployed to the blockchain. Furthermore it also represents the address of the payment channel between two parties for a specific token.


.. _depositing-to-a-channel:

Depositing to a channel
-----------------------
A payment channel is now open between our own address and ``0x61c808d82a3ac53231750dadc13c777b59310bd9``. However, since only one of the nodes has deposited to the channel, only that node can make transfers at this point in time. Now would be the time to notify our counterparty that we have opened a channel with them, so that they can also deposit to the channel. All the counterparty needs in order to do this is the address of the payment channel and a call like the following::

    PATCH /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226

with the payload::

    {"balance": 7331}

If we want to see when the counterparty deposited token, we can then query the channel for the corresponding event::

    GET /api/1/events/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226?from_block=1337

This will return a list of events that has happened in the specific payment channel. The relevant event we are looking for in this case will be::

    {
        "event_type": "ChannelNewBalance",
        "participant": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "balance": 7331,
        "block_number": 54388
    }

If we see the above event we know that our partner has deposited to the channel.
It is possible for both parties to query the state of the specific payment channel by calling::

    GET /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226

This will give you a result similar to those in :ref:`Opening a Channel <opening-a-channel>` that represents the current state of the payment channel.

We have now registered a new token resulting in a new token network. We have opened a channel between two Raiden nodes, and both nodes have deposited to the channel. From here on we can start :ref:`transferring tokens <transferring-tokens>` between the two nodes.

The above is not how a user would normally join an already existing token network. It is the manual way to show how you it works under the hood.

We will take a closer look at how to join already bootstrapped token networks in :ref:`the next scenario <joining-existing-token-network>`. 

``TODO``
* bootstrapping


.. _joining-existing-token-network:

Joining an already existing token network
=========================================
In :ref:`Above scenario <bootstrapping-a-token-network>` we saw how to bootstrap a token network for an unregistered token. In this section we will take a look at the most common way of joining a token network. In most cases users don't want to create a new token network, but they want to join an already existing token network for an ERC20 token that they already hold.

The main focus of this section will be the usage of the ``connect`` and the ``leave`` endpoints. The ``connect`` endpoint allows users to automatically connect to a token network and open channels with other nodes. Furthermore the ``leave`` endpoint allows users to leave a token network by automatically closing and settling all of their open channels.

Let's assume that a user holds 2000 of some awesome ERC20 token (AET). The user knows that a Raiden based token network already exists for this token.


.. _connect:

Connect
-------
Connecting to an already existing token network is quite simple and all you need, is as mentioned above, the address of the token network you want to join and how much of the corresponding token you are willing to use for depositing in channels::

    PUT /api/v1/connection/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671

With a payload representing the amount of tokens that you want to join the network with::

    {
        "funds": 2000
    }

This will automatically connect you to and open channels with three random peers in the token network. Furthermore it will leave 40% of the tokens you join the network with as initially unassigned. This will allow new nodes joining the network to open bi-directionally funded payment channels with our node in the same way that we just opened channels with random nodes already in the network. The default values of opening three channels and leaving 40% of the tokens for new nodes to connect with, can be changed by adding ``"initial_channel_target": our_value`` and ``"joinable_funds_target": our_decimal_number`` to the payload.

We are now connected to the token network for the AET token, and we should have a path to all other nodes that have joined this token network, so that we can transfer tokens to all nodes participating in this network. See the :ref:`Transferring tokens <transferring-tokens>` section for instructions on how to transfer tokens to other nodes.


.. _leave:

Leave
-----
If we at some point want to leave the token network the ``leave`` endpoint is available. This endpoint will take care of closing and settling all open channels in the token network::

    DELETE /api/v1/connection/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671

This call will take some time to finalize, due to the nature of the way that settlement of payment channels work. For more information on the nature of settlement see :doc:`TODO ADD DOCUMENT ON RAIDEN PAYMENT CHANNEL NATURE <link-to-doc.rst>`.


.. _transferring-tokens:

Transferring tokens
===================
So far we know how to bootstrap a token network, how to join an already existing token network, and how to leave a token network. However, we still need to take a look at what Raiden is really all about - transferring tokens from one node to another in off-chain payment channels. Let's assume that we are connected to the token network of the AET token mentioned above. In this case we are connected to five peers, since we used the standard ``connect()`` parameters. 


.. _transfer:

Transfer
--------
Transferring tokens to another node is quite easy. We know the address of the token we want to transfer ``0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671``. All we then need to know is the address of the node we want to transfer to. Let's say the address of the node we want to transfer to is ``0x61c808d82a3ac53231750dadc13c777b59310bd9``::

    POST /api/1/transfers/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671/0x61c808d82a3ac53231750dadc13c777b59310bd9

We also need to know the amount that we want to transfer. We add this as the payload::

    {
        "amount": 42,
    }

An ``"identifier": some_integer`` can also be added to the payload, but it's optional. The identifier's purpose is solely for the benefit of the apps built on top of Raiden in order to provide a way to tag transfers.

If there is a path in the network with enough capacity and the address sending the transfer holds enough tokens to transfer the amount in the payload, the transfer will go through. The receiving node should then be able to see incoming transfers by querying all its open channels. This is done by doing the following for all addresses of open channels::

    GET /api/1/events/channels/0x000397DFD32aFAAE870E6b5FB44154FD43e43224?from_block=1337

Which will return a list of events. All we then need to do is to filter for incoming transfers.

Please note that one of the most powerful features of Raiden is that we can send transfers to anyone connected to the network as long as there is a path to them with enough capacity, and not just to the nodes that we are directly connected to.


.. _close:

Close
-----
If at any point in time we should want to close a specific channel we can do so with the ``close`` endpoint::

    PATCH /api/1/channels/0x000397DFD32aFAAE870E6b5FB44154FD43e43224

with the payload::

    {
        "state":"closed"
    }

When successful this will give a response with a channel object where the state is set to ``"closed"``::

    {
        "channel_address": "0x000397DFD32aFAAE870E6b5FB44154FD43e43224",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671",
        "balance": 350,
        "state": "closed",
        "settle_timeout": 600
    }

Notice how the ``state`` is set to ``"closed"`` compared to the channel objects we've seen earlier where it was ``"open"``.

.. _settle:

Settle
------
Once ``"close"`` has been called then start the settle timeout period, where the counterparty of the channel can provide the last received message from our node. When this timeout settlement timeout period is over, we can finally settle the channel by doing::

    PATCH /api/1/channels/0x000397DFD32aFAAE870E6b5FB44154FD43e43224

with the payload::

    {
        "state":"settled"
    }

this will trigger the ``settle()`` function in the `NettingChannelContract <https://github.com/raiden-network/raiden/blob/a64c03c5faff01c9bd6aab9bd357ba44c113129e/raiden/smart_contracts/NettingChannelContract.sol#L104>`_ smart contract. Once settlement is successful a channel object will be returned::

    {
        "channel_address": "0x000397DFD32aFAAE870E6b5FB44154FD43e43224",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671",
        "balance": 0,
        "state": "settled",
        "settle_timeout": 600
    }

Here it's interesting to notice that the balance of the channel is now ``0`` and that the state is set to ``"settled"``. This means that the net balance that we are owed from our counterparty has now been transferred to us on the blockchain and that the life cycle of the payment channel has ended.


.. _token_swaps:

Token Swaps
===========
Something that has not yet been mentioned in this guide is the functionality of token swaps. A token swap allows Alice and Bob to transfer ``tokenA`` for ``tokenB``. This means that if both Alice and Bob participate in the token networks for ``tokenA`` and ``tokenB``, then they're able to atomically swap some amount of ``tokenA`` for some amount of ``tokenB``. Let's say Alice wants to buy 10 ``tokenB`` for 2 ``tokenA``. If Bob agrees to these terms a swap can be carried out using the ``token_swaps`` endpoint. In the case of the example above, Alice would be the ``maker`` and Bob would be the ``taker``::

    PUT /api/1/token_swaps/0x61c808d82a3ac53231750dadc13c777b59310bd9/1337

Where the first part after ``token_swaps`` is the address of Bob and the second part is an identifier for the token swap. Furthermore we need the following payload::

    {
        "role": "maker",
        "sending_amount": 42,
        "sending_token": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "receiving_amount": 76,
        "receiving_token": "0x2a65aca4d5fc5b5c859090a6c34d164135398226"
    }

There are some interesting parameters to note here. The ``role`` defines whether the address sending the message is the ``maker`` or the ``taker``. The maker call must be carried out before the taker call can be carried out. The ``sending_amount`` and the ``sending_token`` represents the token for which the maker wants to send some amount in return for a ``receiving_token`` and a ``receiving_amount``. So in this specific case Alice is making an offer of 42 of ``tokenA`` with the address ``0xea674fdde714fd979de3edf0f56aa9716b898ec8`` for 76 of ``tokenB`` with the address ``0x2a65aca4d5fc5b5c859090a6c34d164135398226``.

Now all we need is for someone to take the offer. It could be that Alice and Bob has decided on the swap in private and thus Alice simply tells Bob the ``identifier``. Or it could be that the offer is taken by Bob who sees the offer on some decentralized exchange powered by Raiden.
Bob can take the offer by using the same endpoint as above, but with some changes::

    PUT /api/1/token_swaps/0xbbc5ee8be95683983df67260b0ab033c237bde60/1337

Here the address is the address of Alice and note that the identifier is the same as in the request that Alice used to initialise the swap. As with the request above, we also need to add a payload::

    {
        "role": "taker",
        "sending_amount": 76,
        "sending_token": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "receiving_amount": 42,
        "receiving_token": "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    }


Note that the ``role`` is changed from ``maker`` to ``taker``. Furthermore the sending and receiving parameters has been reversed. This is because the swap is now seen from Bob's perspective.

If we now check the balance of the tokens involved for Alice and Bob we should see that they have been updated.



Interacting with the Raiden echo node
=====================================
TODO once the echo node is ready
