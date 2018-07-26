Getting started with the Raiden API
########################################

.. toctree::
  :maxdepth: 3

Introduction
=============
Raiden has a Restful API with URL endpoints corresponding to actions that users can perform with their channels. The endpoints accept and return JSON encoded objects. The API URL path always contains the API version in order to differentiate queries to different API versions. All queries start with: ``/api/<version>/`` where ``<version>`` is an integer representing the current API version.

This section will walk through the steps necessary to participate in a Raiden Token Network. Some different scenarios such as joining an already existing token network, registering a new token network, together with opening, closing and settling channels, will be provided.

Before getting started with below guides, please see :doc:`Overview and Guide <overview_and_guide>`, to make sure that a proper connection to Raiden is established.

Furthermore, to see all available endpoints, please see the :doc:`REST API documentation <rest_api>`.


Scenarios
==========
Below is a series of different scenarios showing different ways a user can interact with the Raiden API.

A good way to check that Raiden was started correctly before proceeding is to check that the Raiden address is the same address as the Ethereum address chosen, when starting the Raiden node:

.. http:example:: curl wget httpie python-requests

   GET /api/1/address HTTP/1.1
   Host: localhost:5001

If this returns the same address, we know that the Raiden node is up and running correctly.

.. _bootstrapping-a-token-network:

Bootstrapping a token network
===============================
In this scenario it is assumed that a user holds some ERC20 token, with address ``0x9aBa529db3FF2D8409A1da4C9eB148879b046700``, which has not yet been registered with Raiden.

The user wants to register the token, which will create a `Token Network <https://raiden-network-specification.readthedocs.io/en/latest/smart_contracts.html#tokennetwork-contract>`_ for that token. For each registered token there is a corresponding token network. Token networks are responsible for opening new payment channels between two parties.


Checking if a token is already registered
-----------------------------------------
One way of checking if a token is already registered is to get the list of all registered tokens and check if the address of the token wanted for interaction exists in the list:

.. http:example:: curl wget httpie python-requests

   GET /api/1/tokens HTTP/1.1
   Host: localhost:5001

If the address of the token exists in the list, see the :ref:`next scenario <joining-existing-token-network>`.
If it does not exist in the list, it is desired to :ref:`register the token <adding-a-token>`.


.. _adding-a-token:

Registering a token
--------------------
In order to register a token only its address is needed. When a new token is registered a Channel Manager contract is deployed, which makes it quite an expensive thing to do in terms of gas usage (costs about 1.8 million gas).

To register a token simply use the endpoint listed below:

.. http:example:: curl wget httpie python-requests

   PUT /api/1/tokens/0x9aBa529db3FF2D8409A1da4C9eB148879b046700 HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

If successful this call will return the address of the freshly created Channel Manager like this:

.. sourcecode:: http

   HTTP/1.1 201 CREATED
   Content-Type: application/json

   {
       "token_network_address": "0xC4F8393fb7971E8B299bC1b302F85BfFB3a1275a"
   }

The token is now registered. However, since the token was just registered, there will be no other Raiden nodes connected to the token network and thus there will be no nodes to connect to. This means that the network for this specific token needs to be bootstrapped. If the address of some other Raiden node that holds some of the tokens is known or it's simply desired to transfer some tokens to another Raiden node in an one-way-channel, it can be done by simply opening a channel with this node. The way to open a channel with another Raiden node is the same whether the partner already holds some tokens or not.


.. _opening-a-channel:

Opening a channel
-------------------
To open a channel with another Raiden node four things are needed: the address of the token, the address of the partner node, the amount of tokens desired for deposit, and the settlement timeout period. With these things ready a channel can be opened:

.. http:example:: curl wget httpie python-requests

   PUT /api/1/channels HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

   {
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
       "balance": 1337,
       "settle_timeout": 600
   }

At this point the specific value of the ``balance`` field isn't too important, since it's always possible to :ref:`deposit more tokens <depositing-to-a-channel>` to a channel if need be.

Successfully opening a channel will return the following information:

.. sourcecode:: http

   HTTP/1.1 201 CREATED
   Content-Type: application/json

   {
       "channel_identifier": "0xfb43f382bbdbf209f854e14b74d183970e26ad5c1fd1b74a20f8f6bb653c1617",
       "token_network_identifier": "0x3C158a20b47d9613DDb9409099Be186fC272421a",
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
       "balance": 1337,
       "state": "opened",
       "settle_timeout": 600
   }

Here it's interesting to notice that a ``channel_identifier`` has been generated. This means that the channel has been created inside the `Token Network <https://raiden-network-specification.readthedocs.io/en/latest/smart_contracts.html#tokennetwork-contract>`_.


.. _depositing-to-a-channel:

Depositing to a channel
------------------------
A payment channel is now open between the user's node and a counterparty. However, since only one of the nodes has deposited to the channel, only that node can make transfers at this point in time. Now would be a good time to notify the counterparty that a channel has been opened with it, so that it can also deposit to the channel. All the counterparty needs in order to do this is to use the endpoint consisting of a combination of the ``token_address`` and the ``participant_address``:

.. http:example:: curl wget httpie python-requests

   PATCH /api/1/channels/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

   {
        "total_deposit": 7331
   }

To see if and when the counterparty deposited tokens, the channel can be queried for the corresponding events. The ``from_block`` parameter in the request represents the block number to query from. (in general the default value should be fine):

.. http:example:: curl wget httpie python-requests

   GET /api/1/events/channels/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/0x61C808D82A3Ac53231750daDc13c777b59310bD9?from_block=1337 HTTP/1.1
   Host: localhost:5001

This will return a list of events that has happened in the specific payment channel. The relevant event in this case is::

    {
        "amount": 682,
        "block_number": 3663408,
        "event": "EventTransferSentSuccess",
        "identifier": 1531927405484,
        "target": "0x25511699C252eeA2678266857C98F459Df97B77c"
    },

From the above event it can be deducted that the counterparty deposited to the channel.
It is possible for both parties to query the state of the specific payment channel by calling:

.. http:example:: curl wget httpie python-requests

   GET /api/1/channels/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
   Host: localhost:5001

This will give us result similar to those in :ref:`Opening a Channel <opening-a-channel>` that represents the current state of the payment channel.

A new token resulting in a new token network has now been registered. A channel between two Raiden nodes has been opened, and both nodes have deposited to the channel. From here on the two nodes can start :ref:`transferring tokens <transferring-tokens>` between each other.

The above is not how a user would normally join an already existing token network. It is only included here to show how it works under the hood.

In :ref:`the next scenario <joining-existing-token-network>` it will be explained how to join already bootstrapped token networks.


.. _joining-existing-token-network:

Joining an already existing token network
==========================================
In :ref:`above scenario <bootstrapping-a-token-network>` it was shown how to bootstrap a token network for an unregistered token. In this section the most common way of joining a token network will be explained. In most cases users don't want to create a new token network, but they want to join an already existing token network for an ERC20 token that they already hold.

The main focus of this section will be the usage of the ``connect`` and the ``leave`` endpoints. The ``connect`` endpoint allows users to automatically connect to a token network and open channels with other nodes. Furthermore the ``leave`` endpoint allows users to leave a token network by automatically closing and settling all of their open channels.

It's assumed that a user holds 2000 of some awesome ERC20 token (AET). The user knows that a Raiden based token network already exists for this token.


.. _connect-to-network:

Connect
---------
Connecting to an already existing token network is quite simple. All that is needed, is as mentioned above, the address of the token network to join and the amount of the corresponding token that the user is willing to deposit in channels:

.. http:example:: curl wget httpie python-requests

   PUT /api/1/connections/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671 HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

   {
       "funds": 2000
   }

This will automatically connect to and open channels with three random peers in the token network, with 20% of the funds deposited to each channel. Furthermore it will leave 40% of the funds initially unassigned. This will allow new nodes joining the network to open bi-directionally funded payment channels with this node in the same way that it just opened channels with random nodes already in the network. The default behaviour of opening three channels and leaving 40% of the tokens for new nodes to connect with, can be changed by adding ``"initial_channel_target": 3`` and ``"joinable_funds_target": 0.4`` to the payload and adjusting the default value.

The user node is now connected to the token network for the AET token, and should have a path to all other nodes that have joined this token network, so that it can transfer tokens to all nodes participating in this network. See the :ref:`Transferring tokens <transferring-tokens>` section for instructions on how to transfer tokens to other nodes.


.. _leave-network:

Leave
------
If at some point it is desired to leave the token network, the ``leave`` endpoint is available. This endpoint will take care of closing and settling all open channels for a specific in the token network:

.. http:example:: curl wget httpie python-requests

   DELETE /api/1/connections/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671 HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

This call will take some time to finalize, due to the nature of the way that settlement of payment channels work. For instance there is a ``settlement_timeout`` period after calling ``close`` that needs to expire before ``settle`` can be called.

.. _transferring-tokens:

Transferring tokens
====================

For the token transfer example it is assumed a node is connected to the token network of the AET token mentioned above. In this case the node is connected to five peers, since the standard ``connect()`` parameters were used.


.. _transfer:

Transfer
---------
Transferring tokens to another node is quite easy. The address of the token desired for transfer is ``0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671``. All that then remains is the address of the target node. Assume the address of the transfer node is ``0x61C808D82A3Ac53231750daDc13c777b59310bD9``:

.. http:example:: curl wget httpie python-requests

   POST /api/1/transfers/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

   {
       "amount": 42
   }

An ``"identifier": some_integer`` can also be added to the payload, but it's optional. The purpose of the identifier is solely for the benefit of the Dapps built on top of Raiden in order to provide a way to tag transfers.

If there is a path in the network with enough capacity and the address sending the transfer holds enough tokens to transfer the amount in the payload, the transfer will go through. The receiving node should then be able to see incoming transfers by querying all its open channels. This is done by doing the following for all addresses of open channels:

.. http:example:: curl wget httpie python-requests

   GET /api/1/events/channels/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671/0x61C808D82A3Ac53231750daDc13c777b59310bD9?from_block=1337 HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

Which will return a list of events. All that then needs to be done is to filter for incoming transfers.

Please note that one of the most powerful features of Raiden is that users can send transfers to anyone connected to the network as long as there is a path to them with enough capacity, and not just to the nodes that a user is directly connected to. This is called *mediated transfers*.


.. _close:

Close
------
If at any point in time it is desired to close a specific channel it can be done with the ``close`` endpoint:

.. http:example:: curl wget httpie python-requests

   PATCH /api/1/channels/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

   {
       "state":"closed"
   }

When successful this will give a response with a channel object where the state is set to ``"closed"``:

.. sourcecode:: http

   HTTP/1.1 200 OK
   Content-Type: application/json

   {
       "channel_identifier": "0xfb43f382bbdbf209f854e14b74d183970e26ad5c1fd1b74a20f8f6bb653c1617",
       "token_network_identifier": "0x3C158a20b47d9613DDb9409099Be186fC272421a",
       "token_address": "0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671",
       "balance": 350,
       "state": "closed",
       "settle_timeout": 600
   }

Notice how the ``state`` is now set to ``"closed"`` compared to the previous channel objects where it was ``"opened"``.

.. _settle:

Settle
------
Once ``close`` has been called, the settle timeout period starts. The channel will be automatically settled as soon as it is over.

The balance of the channel will then be ``0`` and the state ``"settled"``. This means that the net balances that the two parties participating in the channel owe each other has now been transferred on the blockchain and that the life cycle of the payment channel has ended. At this point the blockchain contract has also self-destructed.


Interacting with the Raiden Echo Node
======================================
For easy testing of Raiden, there is a specialized Raiden node running, the "Raiden Echo Node". The Echo Node responds to received transfers by sending a transfer back to the initiator. The echo transfer follows certain rules:

- consecutive transfers with the same ``identifier`` and same ``amount`` from the same address are ignored (as in: the Echo Node just keeps your money)
- the ``echo_identifier`` of all echo transfers is ``identifier + echo_amount``
- transfers with an ``amount`` divisible by ``3`` will be answered with an echo transfer of ``echo_amount = amount - 1``
- transfers with an ``amount = 7`` are special lottery transfers. They will go to a lottery pool. After the Echo Node has received seven lottery transfers, it will choose a winner that receives an echo transfer with ``echo_amount = 49`` and the pool is reset. To query the current number of tickets in the pool, a participant can send another transfer with ``amount = 7`` -- if the participant already takes part in the current draw, the Echo Node will respond with a transfer with ``echo_amount = lottery_pool_size``, otherwise it will enter the pool.
- for a transfer with any other ``amount`` it returns ``echo_amount = amount``


The address of the Echo Node is ``0x02f4b6BC65561A792836212Ebc54434Db0Ab759a`` and it is connected to the Raiden Testnet Token (RTT) with the address ``0x0f114a1e9db192502e7856309cc899952b3db1ed``. The RTT token contract is verified and can be seen in `etherscan <https://ropsten.etherscan.io/address/0x0f114A1E9Db192502E7856309cc899952b3db1ED#code>`_. To interact with the Echo Node, first :ref:`join the RTT network <joining-existing-token-network>`.

You can obtain RTT tokens by calling the ``mint()`` function of the token. In javascript you can load the RTT token contract and call mint as such::

    var rtt_token_abi = [{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[],"name":"mint","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"supply","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"version","outputs":[{"name":"","type":"string"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"amount","type":"uint256"}],"name":"mint","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"amount","type":"uint256"},{"name":"target","type":"address"}],"name":"mintFor","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"},{"name":"_extraData","type":"bytes"}],"name":"approveAndCall","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":false,"type":"function"},{"inputs":[{"name":"_tokenName","type":"string"},{"name":"_tokenSymbol","type":"string"}],"payable":false,"type":"constructor"},{"payable":false,"type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_from","type":"address"},{"indexed":true,"name":"_to","type":"address"},{"indexed":false,"name":"_value","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_spender","type":"address"},{"indexed":false,"name":"_value","type":"uint256"}],"name":"Approval","type":"event"}];
    var rtt_token_address = "0x0f114A1E9Db192502E7856309cc899952b3db1ED";
    var rtt_token = web3.eth.contract(rtt_token_abi).at(rtt_token_address);
    rtt_token.mint({from: eth.accounts[0]}); // adjust to your raiden account and unlock first!


Then you can send a transfer to it via the transfer endpoint:

.. http:example:: curl wget httpie python-requests

   POST /api/1/transfers/0x0f114A1E9Db192502E7856309cc899952b3db1ED/0x02f4b6BC65561A792836212Ebc54434Db0Ab759a HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

   {
       "amount": 1,
       "identifer": 42
   }

Afterwards you can check your events and you should find an ``EventTransferReceivedSuccess`` event with::

    {
        "amount": 1,
        "identifier": 43,
        "initiator": "0x02f4b6BC65561A792836212Ebc54434Db0Ab759a"
    }

According to the rules from above, you should try the same with different amounts, ``3``, ``6``, ``7``, ... -- have fun!
