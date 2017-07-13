Getting started with the Raiden API
###################################


Contents:

.. toctree::
   :maxdepth: 2



Introduction
*************
Raiden has a Restful API with URL endpoints corresponding to actions that the user can perform with his channels. The endpoints accept and return JSON encoded objects. The api url path always contains the api version in order to differentiate queries to different API versions. All queries start with: ``/api/<version>/``

In this guide we will walk through the steps neccessary in order to participate in a Raiden Token Network. We will provide some different scenarios such as joining an already existing token network, registering a new token network, together with opening, closing and settling channels.

Before you get started with below guides, please see :doc:`Overview and Guide <./Overview-And-Guide.rst>`, to make sure that you are connected to Raiden.

Furthermore, to see all available endpoints, please see :doc:`REST API Endpoints <./Rest-Api.rst>`.


Scenarios
*********
Below you'll find a series of different scenarios showing different ways that the Raiden API can be used and interacted with.

A good way to check that you started Raiden correctly before proceeding is to check that your raiden address is the same address as the ethereum address that you chose, when starting the raiden node::

    GET /api/1/address

If this returns your address, you know that your raiden node is connected to the network.

Adding an unregistered token to Raiden
======================================
In this scenario we assume that a user holds some ERC20 tokens of a type that has not yet been registered in the Raiden smart contracts. Let's assume that the address of the token is ``0x9aBa529db3FF2D8409A1da4C9eB148879b046700``.

The user wants to register the token, which will create a `Channel Manager <https://github.com/raiden-network/raiden/blob/master/raiden/smart_contracts/ChannelManagerContract.sol>`_. For each registered token there is a channel manager. Channel managers are responsible of opening new payment channels between two parties.


Checking if a token is already registered
-----------------------------------------
One way of checking if a token is already registered is to get the list of all registered tokens and check if the address of the token you want to interact with exists in the list::

    GET /api/1/tokens

If the address of the token you want to interact with exists in the list, see the :ref:`next scenario <scenario2>`.
If it does not exist in the list, we need to :ref:`register the token <adding-a-token>`.


.. _adding-a-token:
Registering a token
-------------------
In order to register a token all we need is the address of the token. When a new token is registered a Channel Manager contract is deployed, which makes it quite an expensive thing to do in terms of gas usage ``TODO insert estimated gas price``.

To register a token simply use the endpoint listed below::

    PUT /api/1/tokens/0x9aBa529db3FF2D8409A1da4C9eB148879b046700

If successful this call will return the address of the fresly created Channel Manager like this::

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

Succesfully opening a channel will return the following information::

    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
        "balance": 1337,
        "state": "open",
        "settle_timeout": 600
    }

Here it's interesting to notice that a `"channel_address"` has been generated. This means that a `Netting Channel contract <https://github.com/raiden-network/raiden/blob/master/raiden/smart_contracts/NettingChannelContract.sol>`_ has been deployed to the blockchain. Furthermore it also represents the address of the payment channel between two parties for a specific token.


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

Above is not how a user would normally join an already existing token network. We will take a closer look at how to join already bootstrapped token networks in :ref:`the next scenario <scenario2>`. Above shows how a user would bootstrap a new token network. This would not be the steps that most users would have to follow, since these steps are only needed when bootstrapping a new token network.


* bootstrapping
* TODO should the addresses used in the documentation actually be deployed contracts etc., or is it fine that it's just some random adresses?


.. _scenario2:
Joining an already existing token network
=========================================



.. _transferring-tokens:
Transferring tokens
===================





Interacting with the Raiden echo node
=====================================

