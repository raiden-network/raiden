Getting started with the Raiden API
########################################

.. toctree::
  :maxdepth: 3

Introduction
=============
Raiden has a Restful API with URL endpoints corresponding to actions that users can perform with their channels. The endpoints accept and return JSON encoded objects. The API URL path always contains the API version in order to differentiate queries to different API versions. All queries start with: ``/api/<version>/`` where ``<version>`` is an integer representing the current API version.

This section will walk through the steps necessary to participate in a Raiden Token Network. Some different scenarios such as joining an already existing token network, registering a new token network, together with opening, closing and settling channels, will be provided.

Before getting started with below guides, please see :doc:`Overview and Guide <overview_and_guide>`, to make sure that a proper connection to Raiden is established.

Furthermore, to see all available endpoints, please see :doc:`REST API Endpoints <rest_api>`.


Scenarios
==========
Below is a series of different scenarios showing different ways a user can interact with the Raiden API.

A good way to check that Raiden was started correctly before proceeding is to check that the Raiden address is the same address as the Ethereum address chosen, when starting the Raiden node::

    GET /api/1/address

If this returns the same address, we know that the Raiden node is up and running correctly.

.. _bootstrapping-a-token-network:

Bootstrapping a token network
===============================
In this scenario it is assumed that a user holds some ERC20 token, with address ``0x9aBa529db3FF2D8409A1da4C9eB148879b046700``, which has not yet been registered with Raiden.

The user wants to register the token, which will create a `Channel Manager <https://github.com/raiden-network/raiden/blob/a64c03c5faff01c9bd6aab9bd357ba44c113129e/raiden/smart_contracts/ChannelManagerContract.sol>`_. For each registered token there is a corresponding channel manager. Channel managers are responsible for opening new payment channels between two parties.


Checking if a token is already registered
-----------------------------------------
One way of checking if a token is already registered is to get the list of all registered tokens and check if the address of the token wanted for interaction exists in the list::

    GET /api/1/tokens

If the address of the token exists in the list, see the :ref:`next scenario <joining-existing-token-network>`.
If it does not exist in the list, it is desired to :ref:`register the token <adding-a-token>`.


.. _adding-a-token:

Registering a token
--------------------
In order to register a token only its address is needed. When a new token is registered a Channel Manager contract is deployed, which makes it quite an expensive thing to do in terms of gas usage (costs about 1.8 million gas).

To register a token simply use the endpoint listed below::

    PUT /api/1/tokens/0x9aBa529db3FF2D8409A1da4C9eB148879b046700

If successful this call will return the address of the freshly created Channel Manager like this::

    {"channel_manager_address": "0xC4F8393fb7971E8B299bC1b302F85BfFB3a1275a"}

The token is now registered. However, since the token was just registered, there will be no other Raiden nodes connected to the token network and hence no nodes to connect to. This means that the network for this specific token needs to be bootstrapped. If the address of some other Raiden node that holds some of the tokens is known  or it's simply desired to transfer some tokens to another Raiden node in a one-way-channel, it can be done by simply opening a channel with this node. The way to open a channel with another Raiden node is the same whether the partner already holds some tokens or not.


.. _opening-a-channel:

Opening a channel
-------------------
To open a channel with another Raiden node four things are needed: the address of the token, the address of the partner node, the amount of tokens desired for deposit, and the settlement timeout period. With these things ready a channel can be opened::

    PUT /api/1/channels

With the payload::

    {
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
        "balance": 1337,
        "settle_timeout": 600
    }

At this point the specific value of the ``balance`` field isn't too important, since it's always possible to :ref:`deposit more tokens <depositing-to-a-channel>` to a channel if need be.

Successfully opening a channel will return the following information::

    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
        "balance": 1337,
        "state": "open",
        "settle_timeout": 600
    }

Here it's interesting to notice that a ``channel_address`` has been generated. This means that a `Netting Channel contract <https://github.com/raiden-network/raiden/blob/a64c03c5faff01c9bd6aab9bd357ba44c113129e/raiden/smart_contracts/NettingChannelContract.sol>`_ has been deployed to the blockchain. Furthermore it also represents the address of the payment channel between two parties for a specific token.


.. _depositing-to-a-channel:

Depositing to a channel
------------------------
A payment channel is now open between the user's node and a counterparty with the address ``0x61c808d82a3ac53231750dadc13c777b59310bd9``. However, since only one of the nodes has deposited to the channel, only that node can make transfers at this point in time. Now would be a good time to notify the counterparty that a channel has been opened with it, so that it can also deposit to the channel. All the counterparty needs in order to do this is the address of the payment channel::

    PATCH /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226

with the payload::

    {
        "balance": 7331
    }

To see if and when the counterparty deposited tokens, the channel can be queried for the corresponding events. The ``from_block`` parameter in the request represents the block number to query from::

    GET /api/1/events/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226?from_block=1337

This will return a list of events that has happened in the specific payment channel. The relevant event in this case is::

    {
        "event_type": "ChannelNewBalance",
        "participant": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "balance": 7331,
        "block_number": 54388
    }

From above event it can be deducted that the counterparty deposited to the channel.
It is possible for both parties to query the state of the specific payment channel by calling::

    GET /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226

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
Connecting to an already existing token network is quite simple. All that is needed, is as mentioned above, the address of the token network to join and the amount of the corresponding token that the user is willing to deposit in channels::

    PUT /api/v1/connections/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671

With the payload::

    {
        "funds": 2000
    }

This will automatically connect to and open channels with three random peers in the token network, with 20% of the funds deposited to each channel. Furthermore it will leave 40% of the funds initially unassigned. This will allow new nodes joining the network to open bi-directionally funded payment channels with this node in the same way that it just opened channels with random nodes already in the network. The default behaviour of opening three channels and leaving 40% of the tokens for new nodes to connect with, can be changed by adding ``"initial_channel_target": 3`` and ``"joinable_funds_target": 0.4`` to the payload and adjusting the default value.

The user node is now connected to the token network for the AET token, and should have a path to all other nodes that have joined this token network, so that it can transfer tokens to all nodes participating in this network. See the :ref:`Transferring tokens <transferring-tokens>` section for instructions on how to transfer tokens to other nodes.


.. _leave-network:

Leave
------
If at some point it is desired to leave the token network, the ``leave`` endpoint is available. This endpoint will take care of closing and settling all open channels for a specific in the token network::

    DELETE /api/v1/connections/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671

This call will take some time to finalize, due to the nature of the way that settlement of payment channels work. For instance there is a ``settlement_timeout`` period after calling ``close`` that needs to expire before ``settle`` can be called.

For reasons of speed and financial efficiency the ``leave`` call will only close and settle channels for which the node has received a transfer.

To override the default behaviour and leave all open channels add the following payload::

  {
      "only_receiving_channels": false
  }


.. _transferring-tokens:

Transferring tokens
====================

For the token transfer example it is assumed a node is connected to the token network of the AET token mentioned above. In this case the node is connected to five peers, since the standard ``connect()`` parameters were used.


.. _transfer:

Transfer
---------
Transferring tokens to another node is quite easy. The address of the token desired for transfer is known ``0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671``. All that then remains is the address of the target node. Assume the address of the transfer node is ``0x61c808d82a3ac53231750dadc13c777b59310bd9``::

    POST /api/1/transfers/0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671/0x61c808d82a3ac53231750dadc13c777b59310bd9

The amount of the transfer is specified in the payload::

    {
        "amount": 42
    }

An ``"identifier": some_integer`` can also be added to the payload, but it's optional. The purpose of the identifier is solely for the benefit of the Dapps built on top of Raiden in order to provide a way to tag transfers.

If there is a path in the network with enough capacity and the address sending the transfer holds enough tokens to transfer the amount in the payload, the transfer will go through. The receiving node should then be able to see incoming transfers by querying all its open channels. This is done by doing the following for all addresses of open channels::

    GET /api/1/events/channels/0x000397DFD32aFAAE870E6b5FB44154FD43e43224?from_block=1337

Which will return a list of events. All that then needs to be done is to filter for incoming transfers.

Please note that one of the most powerful features of Raiden is that users can send transfers to anyone connected to the network as long as there is a path to them with enough capacity, and not just to the nodes that a user is directly connected to. This is called ``mediated transfers``.


.. _close:

Close
------
If at any point in time it is desired to close a specific channel it can be done with the ``close`` endpoint::

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

Notice how the ``state`` is now set to ``"closed"`` compared to the previous channel objects where it was ``"open"``.

.. _settle:

Settle
------
Once ``close`` has been called, the settle timeout period starts. During this period the counterparty of the node who closed the channel has to provide its last received message. When the settlement timeout period is over, the channel can finally be settled by doing::

    PATCH /api/1/channels/0x000397DFD32aFAAE870E6b5FB44154FD43e43224

with the payload::

    {
        "state":"settled"
    }

this will trigger the ``settle()`` function in the `NettingChannel <https://github.com/raiden-network/raiden/blob/a64c03c5faff01c9bd6aab9bd357ba44c113129e/raiden/smart_contracts/NettingChannelContract.sol#L104>`_ smart contract. Once settlement is successful a channel object will be returned::

    {
        "channel_address": "0x000397DFD32aFAAE870E6b5FB44154FD43e43224",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xc9d55C7bbd80C0c2AEd865e9CA13D015096ce671",
        "balance": 0,
        "state": "settled",
        "settle_timeout": 600
    }

Here it's interesting to notice that the balance of the channel is now ``0`` and that the state is set to ``"settled"``. This means that the netted balances that the two parties participating in the channel owe each other has now been transferred on the blockchain and that the life cycle of the payment channel has ended. At this point the blockchain contract has also self-destructed.


.. _token-swaps:

Token Swaps
=============

.. warning:: Token swaps have not been tested sufficiently and are still in an experimental mode.

Something that has not yet been mentioned in this guide is the functionality of token swaps. A token swap allows Alice and Bob to exchange ``tokenA`` for ``tokenB``. This means that if both Alice and Bob participate in the token networks for ``tokenA`` and ``tokenB``, then they're able to atomically swap some amount of ``tokenA`` for some amount of ``tokenB``. Let's say Alice wants to buy 10 ``tokenB`` for 2 ``tokenA``. If Bob agrees to these terms a swap can be carried out using the ``token_swaps`` endpoint. In the case of the example above, Alice would be the ``maker`` and Bob would be the ``taker``::

    PUT /api/1/token_swaps/0x61c808d82a3ac53231750dadc13c777b59310bd9/1337

Where the first part after ``token_swaps`` is the address of Bob and the second part is an identifier for the token swap. Furthermore the following payload is needed::

    {
        "role": "maker",
        "sending_amount": 42,
        "sending_token": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "receiving_amount": 76,
        "receiving_token": "0x2a65aca4d5fc5b5c859090a6c34d164135398226"
    }

There are some interesting parameters to note here. The ``role`` defines whether the address sending the message is the ``maker`` or the ``taker``. The maker call must be carried out before the taker call can be carried out. The ``sending_amount`` and the ``sending_token`` represent the token for which the maker wants to send some amount in return for a ``receiving_token`` and a ``receiving_amount``. So in this specific case Alice is making an offer of 42 of ``tokenA`` with the address ``0xea674fdde714fd979de3edf0f56aa9716b898ec8`` for 76 of ``tokenB`` with the address ``0x2a65aca4d5fc5b5c859090a6c34d164135398226``.

Now all that is needed is for someone to take the offer. It could be that Alice and Bob have decided on the swap in private and thus Alice simply tells Bob the ``identifier``. Or it could be that the offer is taken by Bob who sees the offer on some decentralized exchange powered by Raiden.
Bob can take the offer by using the same endpoint as above, but with some changes::

    PUT /api/1/token_swaps/0xbbc5ee8be95683983df67260b0ab033c237bde60/1337

Here the address is the address of Alice and note that the identifier is the same as in the request that Alice used to initialise the swap. As with the request above, a payload is needed::

    {
        "role": "taker",
        "sending_amount": 76,
        "sending_token": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "receiving_amount": 42,
        "receiving_token": "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    }


Note that the ``role`` is changed from ``maker`` to ``taker``. Furthermore the sending and receiving parameters have been reversed. This is because the swap is now seen from Bob's perspective.

At this point Alice's and Bob's balances should reflect the state after the swap.



Interacting with the Raiden Echo Node
======================================
For easy testing of Raiden, there is a specialized Raiden node running, the "Raiden Echo Node". The Echo Node responds to received transfers by sending a transfer back to the initiator. The echo transfer follows certain rules:

- consecutive transfers with the same ``identifier`` and same ``amount`` from the same address are ignored (as in: the Echo Node just keeps your money)
- the ``echo_identifier`` of all echo transfers is ``identifier + echo_amount``
- transfers with an ``amount`` divisible by ``3`` will be answered with an echo transfer of ``echo_amount = amount - 1``
- transfers with an ``amount = 7`` are special lottery transfers. They will go to a lottery pool. After the Echo Node has received seven lottery transfers, it will choose a winner that receives an echo transfer with ``echo_amount = 49`` and the pool is reset. To query the current number of tickets in the pool, a participant can send another transfer with ``amount = 7`` -- if the participant already takes part in the current draw, the Echo Node will respond with a transfer with ``echo_amount = lottery_pool_size``, otherwise it will enter the pool.
- for a transfer with any other ``amount`` it returns ``echo_amount = amount``


The address of the Echo Node is ``0x02f4b6bc65561a792836212ebc54434db0ab759a`` and it is connected to the Raiden Testnet Token (RTT) with the address ``0x0f114a1e9db192502e7856309cc899952b3db1ed``. The RTT token contract is verified and can be seen in `etherscan <https://ropsten.etherscan.io/address/0x0f114a1e9db192502e7856309cc899952b3db1ed#code>`_. To interact with the Echo Node, first :ref:`join the RTT network <joining-existing-token-network>`.

You can obtain RTT tokens by calling the ``mint()`` function of the token. In javascript you can load the RTT token contract and call mint as such::

    var rtt_token_abi = [{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[],"name":"mint","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"supply","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"version","outputs":[{"name":"","type":"string"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"amount","type":"uint256"}],"name":"mint","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"amount","type":"uint256"},{"name":"target","type":"address"}],"name":"mintFor","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"},{"name":"_extraData","type":"bytes"}],"name":"approveAndCall","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":false,"type":"function"},{"inputs":[{"name":"_tokenName","type":"string"},{"name":"_tokenSymbol","type":"string"}],"payable":false,"type":"constructor"},{"payable":false,"type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_from","type":"address"},{"indexed":true,"name":"_to","type":"address"},{"indexed":false,"name":"_value","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_spender","type":"address"},{"indexed":false,"name":"_value","type":"uint256"}],"name":"Approval","type":"event"}];
    var rtt_token_address = "0x0f114a1e9db192502e7856309cc899952b3db1ed";
    var rtt_token = web3.eth.contract(rtt_token_abi).at(rtt_token_address);
    rtt_token.mint({from: eth.accounts[0]}); // adjust to your raiden account and unlock first!


Then you can send a transfer to it via the transfer endpoint: ``POST /api/1/transfers/0x0f114a1e9db192502e7856309cc899952b3db1ed/0x02f4b6bc65561a792836212ebc54434db0ab759a`` and with a payload containing the amount you want to send and an optional identifier::

    {
        "amount": 1,
        "identifer": 42,
    }

Afterwards you can check your events and you should find an ``EventTransferReceivedSuccess`` event with::

    {
        "amount": 1,
        "identifier": 43,
        "initiator": "0x02f4b6bc65561a792836212ebc54434db0ab759a"
    }

According to the rules from above, you should try the same with different amounts, ``3``, ``6``, ``7``, ... -- have fun!
