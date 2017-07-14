Getting started with the Raiden API
###################################


Contents:

.. toctree::
   :maxdepth: 2



Introduction
*************
Raiden has a Restful API with URL endpoints corresponding to actions that the user can perform with his channels. The endpoints accept and return JSON encoded objects. The api url path always contains the api version in order to differentiate queries to different API versions. All queries start with: ``/api/<version>/``

In this guide we will walk through the steps necessary in order to participate in a Raiden Token Network. We will provide some different scenarios such as joining an already existing token network, registering a new token network, together with opening, closing and settling channels.

Before you get started with below guides, please see :doc:`Overview and Guide <./Overview-And-Guide.rst>`, to make sure that you are connected to Raiden.

Furthermore, to see all available endpoints, please see :doc:`REST API Endpoints <./Rest-Api.rst>`.


Scenarios
*********
Below you'll find a series of different scenarios showing different ways that the Raiden API can be used and interacted with.

A good way to check that you started Raiden correctly before proceeding is to check that your Raiden address is the same address as the ethereum address that you chose, when starting the Raiden node::

    GET /api/1/address

If this returns your address, you know that your Raiden node is connected to the network.

.. _bootstrapping-a-token-network:
Bootstrapping a token network
=============================
In this scenario we assume that a user holds some ERC20 tokens of a type that has not yet been registered in the Raiden smart contracts. Let's assume that the address of the token is ``0x9aBa529db3FF2D8409A1da4C9eB148879b046700``.

The user wants to register the token, which will create a `Channel Manager <https://github.com/Raiden-network/Raiden/blob/master/Raiden/smart_contracts/ChannelManagerContract.sol>`_. For each registered token there is a channel manager. Channel managers are responsible of opening new payment channels between two parties.


Checking if a token is already registered
-----------------------------------------
One way of checking if a token is already registered is to get the list of all registered tokens and check if the address of the token you want to interact with exists in the list::

    GET /api/1/tokens

If the address of the token you want to interact with exists in the list, see the :ref:`next scenario <joining-existing-token-network>`.
If it does not exist in the list, we need to :ref:`register the token <adding-a-token>`.


.. _adding-a-token:
Registering a token
-------------------
In order to register a token all we need is the address of the token. When a new token is registered a Channel Manager contract is deployed, which makes it quite an expensive thing to do in terms of gas usage ``TODO insert estimated gas price``.

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

Here it's interesting to notice that a `"channel_address"` has been generated. This means that a `Netting Channel contract <https://github.com/Raiden-network/Raiden/blob/master/Raiden/smart_contracts/NettingChannelContract.sol>`_ has been deployed to the blockchain. Furthermore it also represents the address of the payment channel between two parties for a specific token.


.. _depositing-to-a-channel:
Depositing to a channel
-----------------------
A payment channel is now open between our own address and ``0x61c808d82a3ac53231750dadc13c777b59310bd9``. However, since only one of the nodes has deposited to the channel, only that node can make transfers at this point in time. Now would be the time to notify our counterparty that we have opened a channel with him/her/it, so that they can also deposit to the channel. All the counterparty needs in order to do this is the address of the payment channel::

    PATCH /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226

with the payload::

    {"balance": 7331}

We can then query the channel for events to see when our counterparty deposits::

    GET /api/1/events/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226?from_block=1337

This will return a list of events that has happened in the specific payment channel. The relevant event we are looking for in this case will be::

    {
        "event_type": "ChannelNewBalance",
        "participant": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "balance": 7331,
        "block_number": 54388
    }

If we see above event we know that our partner has deposited to the channel.
It is possible for both parties to query the state of the specific payment channel by calling::

    GET /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226

This will give you a result similar to those in :ref:`Opening a Channel <opening-a-channel>` that represents the current state of the payment channel.

We have now registered a new token resulting in a new token network. We have opened a channel between two Raiden nodes, and both nodes have deposited to the channel. From here on we can start :ref:`transferring tokens <transferring-tokens>` between the two nodes.

Above is not how a user would normally join an already existing token network. We will take a closer look at how to join already bootstrapped token networks in :ref:`the next scenario <joining-existing-token-network>`. Above shows how a user would bootstrap a new token network. This would not be the steps that most users would have to follow, since these steps are only needed when bootstrapping a new token network.


* bootstrapping
* TODO should the addresses used in the documentation actually be deployed contracts etc., or is it fine that it's just some random addresses?



.. _joining-existing-token-network:
Joining an already existing token network
=========================================
In :ref:`Above scenario <bootstrapping-a-token-network>` we saw how to bootstrap a token network for an unregistered token. In this section we will take a look at the most common way of joining a token network. In most cases users don't want to create a new token network, but they want to join an already existing token network for an ERC20 token that they already hold.

The main focus of this section will be the usage of the ``connect`` and the ``leave`` endpoints. The ``connect`` endpoint allows users to automatically connect to a token network and open channels with other nodes. Furthermore the ``leave`` endpoint allows users to leave a token network by automatically closing and settling all the open payment channels of the user.

Let's assume that a user holds 2000 of some awesome ERC20 token (AET). The user knows that a Raiden based token network already exists for this token.


.. _connect:
Connect
-------
Connecting to an already existing token network is quite simple and all you need, is as mentioned above, the address of the token network you want to join and some of the corresponding tokens::

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
So far we know how to bootstrap a token network, how to join an already existing token network, and how to leave a token network. However, we still need to take a look at what Raiden is really all about - transferring tokens from one node to another in off-chain payment channels. Let's assume that we are connected to the token network of the AET token mentioned above. In this case we are connected to five peers, since we used that standard ``connect()`` parameters. 


.. _transfer:
Transfer
--------
Transferring tokens to another node is quite easy. We know the address of the token we want to transfer ``0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671``. All we then need to know is the address of the node we want to transfer to. Let's say the address of the node we want to transfer to is ``0x61c808d82a3ac53231750dadc13c777b59310bd9``::

    POST /api/1/transfers/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671/0x61c808d82a3ac53231750dadc13c777b59310bd9

We also need to know the amount that we want to transfer. We add this as the payload::

    {
        "amount": 42,
    }

An ``"identifier": some_integer`` can also be added to the payload, but it's optional.

If there is a path in the network with enough capacity and the address sending the transfer holds enough tokens to transfer the amount in the payload, the transfer will go through. The receiving node should then be able to see incoming transfers by querying all its open channels. This is done by doing the following for all addresses of open channels::

    GET /api/1/events/channels/0x000397DFD32aFAAE870E6b5FB44154FD43e43224?from_block=1337

Which will return a list of events. All we then need to do is to filter for incoming transfers.

Please note that one of the most powerful features of Raiden is that we can send transfers to anyone connected to the network as long as there is a path with enough capacity, and not just to the nodes that we are directly connected to.
.. _close:
Close
-----


.. _settle:
Settle
------




Interacting with the Raiden echo node
=====================================

