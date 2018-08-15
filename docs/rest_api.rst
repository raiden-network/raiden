Raiden's API Documentation
##########################

.. toctree::
   :maxdepth: 2

Introduction
*************
Raiden has a Restful API with URL endpoints corresponding to user-facing interaction allowed by a Raiden node. The endpoints accept and return JSON encoded objects. The api url path always contains the api version in order to differentiate queries to
different API versions. All queries start with: ``/api/<version>/``



JSON Object Encoding
********************

The objects that are sent to and received from the API are JSON-encoded. Following are the common objects used in the API.

Channel Object
===============
::

    {
       "channel_identifier": "0xfb43f382bbdbf209f854e14b74d183970e26ad5c1fd1b74a20f8f6bb653c1617",
       "token_network_identifier": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226",
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
       "balance": 35000000,
       "state": "opened",
       "settle_timeout": 500,
       "reveal_timeout": 40
    }



A channel object consists of a

- ``channel_identifier`` should be a ``string`` containing the hexadecimal identifier of the
  channel.

- ``partner_address`` should be a ``string`` containing the EIP55-encoded address of the
  partner with whom we have opened a channel.

- ``token_address`` should be a ``string`` containing the EIP55-encoded address of the
  token we are trading in the channel.

- ``token_network_identifier`` should be a ``string`` containing the EIP55-encoded address of the
  token network the channel is part of.

- ``balance`` should be an integer of the amount of the ``token_address`` token we have available for payments.

- ``state`` should be the current state of the channel represented by a string.
  Possible value are:
  - ``'opened'``: The channel is open and tokens are tradeable
  - ``'closed'``: The channel has been closed by a participant
  - ``'settled'``: The channel has been closed by a participant and also settled.

- ``'settle_timeout'``: The number of blocks that are required to be mined from the time that ``close()`` is called until the channel can be settled with a call to ``settle()``.

- ``'reveal_timeout'``: The maximum number of blocks allowed between the setting of a hashlock and the revealing of the related secret.

Event Object
==============

Channels events are encoded as json objects with the event arguments as attributes
of the dictionary, with one difference. The ``event_type`` and the ``block_number`` are also added for all events to easily distinguish between events.

Errors
======

For any non-successful http status code, e.g. :http:statuscode:`409` or :http:statuscode:`400` there will be an accompanying ``errors`` field in the response json which you can check for more information on what went wrong with your request.

Endpoints
***********

Following are the available API endpoints with which you can interact with Raiden.

Querying Information About Your Raiden Node
===============================================

.. http:get:: /api/(version)/address

   Query your address. When raiden starts, you choose an ethereum address which will also be your raiden address.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/address HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "our_address": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226"
      }

Deploying
=========

.. http:put:: /api/(version)/tokens/(token_address)

   Registers a token. If a token is not registered yet (i.e.: A token network for that token does not exist in the registry), we need to register it by deploying a token network contract for that token.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      PUT /api/1/tokens/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 201 CREATED
      Content-Type: application/json

      {
          "token_network_address": "0xC4F8393fb7971E8B299bC1b302F85BfFB3a1275a"
      }

   :statuscode 201: A token network for the token has been successfully created.
   :statuscode 202: Creation of the token network for the token has been started but did not finish yet. Please check again once the related transaction has been mined.
   :statuscode 402: Insufficient ETH to pay for the gas of the register on-chain transaction
   :statuscode 404: The given token address is invalid.
   :statuscode 409:
    - The token was already registered before, or
    - The registering transaction failed.
   :resjson address token_network_address: The deployed token networks address.

Querying Information About Channels and Tokens
==============================================

.. http:get:: /api/(version)/channels

   Get a list of all unsettled channels.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/channels HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
          {
              "token_network_identifier": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
              "channel_identifier": "0xa24f51685de3effe829f7c2e94b9db8e9e1b17b137da59fa727a793ae2cae776",
              "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
              "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
              "balance": 35000000,
              "state": "open",
              "settle_timeout": 100,
              "reveal_timeout": 30
          }
      ]

   :statuscode 200: Successful query
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/channels/(token_address)/(partner_address)

   Query information about one of your channels. The channel is specified by the address of the token and the partner's address.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "token_network_identifier": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
          "channel_identifier": "0xa24f51685de3effe829f7c2e94b9db8e9e1b17b137da59fa727a793ae2cae776",
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": 35000000,
          "state": "open",
          "settle_timeout": 100,
          "reveal_timeout": 30
      }

   :statuscode 200: Successful query
   :statuscode 404:
    - The given token and partner addresses are not valid eip55-encoded Ethereum addresses or
    - Channel does not exist
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/tokens

   Returns a list of addresses of all registered tokens.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/tokens HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
          "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "0x61bB630D3B2e8eda0FC1d50F9f958eC02e3969F6"
      ]

   :statuscode 200: Successful query
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/tokens/(token_address)/partners

   Returns a list of all partners with whom you have non-settled channels for a certain token.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/tokens/0x61bB630D3B2e8eda0FC1d50F9f958eC02e3969F6/partners HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
         {
             "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
             "channel": "/api/<version>/channels/0x2a65Aca4D5fC5B5C859090a6c34d164135398226"
         }
      ]

   :statuscode 200: Successful query
   :statuscode 302: If the user accesses the channel link endpoint
   :statuscode 404: If the token does not exist/the token address is invalid
   :statuscode 500: Internal Raiden node error
   :resjsonarr address partner_address: The partner we have a channel with
   :resjsonarr link channel: A link to the channel resource

Channel Management
==================

.. http:put:: /api/(version)/channels

   Opens (i. e. creates) a channel.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      PUT /api/1/channels HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": 35000000,
          "settle_timeout": 500
      }

   :reqjson int balance: Initial deposit to make to the channel.

   The request's payload is a channel object; since it is a new channel, its ``channel_address``
   and ``status`` fields will be ignored and can be omitted.

   The request to the endpoint should later return the fully created channel object
   from which we can find the address of the channel.

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 201 CREATED
      Content-Type: application/json

      {
          "channel_address": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226",
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": 35000000,
          "state": "open",
          "settle_timeout": 500,
          "reveal_timeout": 30
      }

   :statuscode 201: Channel created successfully
   :statuscode 202: Creation of the channel has been started but did not finish yet. Please check again once the related transaction has been mined.
   :statuscode 400: Provided JSON is in some way malformed
   :statuscode 402: Insufficient ETH to pay for the gas of the channel open on-chain transaction
   :statuscode 408: Deposit event was not read in time by the Ethereum node
   :statuscode 409: Invalid input, e. g. too low a settle timeout
   :statuscode 500: Internal Raiden node error

.. http:patch:: /api/(version)/channels/(token_address)/(partner_address)

   This request is used to close a channel or to increase the deposit in it.

   **Example Request (close channel)**:

   .. http:example:: curl wget httpie python-requests

      PATCH /api/1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "state": "closed"
      }

   **Example Request (increase deposit)**:

   .. http:example:: curl wget httpie python-requests

      PATCH /api/1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "total_deposit": 100
      }

   :reqjson string state: Desired new state; the only valid choice is ``"closed"``
   :reqjson int total_deposit: The increased total deposit

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "channel_address": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226",
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": 35000000,
          "state": "closed",
          "settle_timeout": 100,
          "reveal_timeout": 30
      }

   :statuscode 200: Success
   :statuscode 202: The requested action has been started but did not finish yet. Please check again once the related transaction has been mined.
   :statuscode 400:
    - The provided JSON is in some way malformed, or
    - there is nothing to do since neither ``state`` nor ``total_deposit`` have been given, or
    - the value of ``state`` is not a valid channel state.
   :statuscode 402: Insufficient balance to do a deposit, or insufficient ETH to pay for the gas of the on-chain transaction
   :statuscode 408: Deposit event was not read in time by the Ethereum node
   :statuscode 409:
    - Provided channel does not exist or
    - ``state`` and ``total_deposit`` have been attempted to update in the same request or
    - attempt to deposit token amount lower than on-chain balance of the channel
    - attempt to deposit more tokens than the testing limit
   :statuscode 500: Internal Raiden node error

Connection Management
=====================

.. http:get:: /api/(version)/connections

   Query details of all joined token networks.

   The request will return a JSON object where each key is a token address for which you have open channels.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/connections HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "0x2a65Aca4D5fC5B5C859090a6c34d164135398226": {
              "funds": 100,
              "sum_deposits": 67,
              "channels": 3
          },
          "0x0f114A1E9Db192502E7856309cc899952b3db1ED": {
              "funds": 49
              "sum_deposits": 31,
              "channels": 1
          }
      }

   :resjsonarr int funds: Funds from last connect request
   :resjsonarr int sum_deposits: Sum of deposits of all currently open channels
   :resjsonarr int channels: Number of channels currently open for that token
   :statuscode 200: For a successful query
   :statuscode 500: Internal Raiden node error

.. http:put:: /api/(version)/connections/(token_address)

   Automatically join a token network. The request will only return once all blockchain calls for
   opening and/or depositing to a channel have completed.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      PUT /api/1/connections/0x2a65Aca4D5fC5B5C859090a6c34d164135398226 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "funds": 1337
      }

   :reqjson int funds: amount of funding you want to put into the network
   :reqjson int initial_channel_target: number of channels to open proactively
   :reqjson float joinable_funds_target: fraction of funds that will be used to join channels opened by other participants
   :statuscode 202: The joining of the token network for the token has been started but did not finish yet. Please check again once the related transaction has been mined.
   :statuscode 204: For a successful connection creation
   :statuscode 402: If any of the channel deposits fail due to insufficient ETH balance to pay for the gas of the on-chain transactions
   :statuscode 408: If a timeout happened during any of the transactions
   :statuscode 409: If any of the provided input to the call is invalid.
   :statuscode 500: Internal Raiden node error

.. http:delete:: /api/(version)/connections/(token_address)

   Leave a token network. The request will only return once all blockchain calls for closing/settling a channel have completed.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      DELETE /api/1/connection HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
          "0x41BCBC2fD72a731bcc136Cf6F7442e9C19e9f313",
          "0x5A5f458F6c1a034930E45dC9a64B99d7def06D7E",
          "0x8942c06FaA74cEBFf7d55B79F9989AdfC85C6b85"
      ]

   The response is a list with the addresses of all closed channels.

   :statuscode 200: For successfully leaving a token network
   :statuscode 500: Internal Raiden node error

Payments
========

.. http:post:: /api/(version)/payments/(token_address)/(target_address)

   Initiate a payment.

   The request will only return once the payment either succeeded or failed. A payment can fail due to the expiration of a lock, the target being offline, channels on the path to the target not having enough ``settle_timeout`` and ``reveal_timeout`` in order to allow the payment to be propagated safely e.t.c

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/1/payments/0x2a65Aca4D5fC5B5C859090a6c34d164135398226/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "amount": 200,
          "identifier": 42
      }

   :reqjson int amount: Amount to be sent to the target
   :reqjson int identifier: Identifier of the payment (optional)

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "initiator_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "target_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226",
          "amount": 200,
          "identifier": 42
      }

   :statuscode 200: Successful payment
   :statuscode 400: If the provided json is in some way malformed
   :statuscode 402: If the payment can't start due to insufficient balance
   :statuscode 408: If a timeout happened during the payment
   :statuscode 409: If the address or the amount is invalid or if there is no path to the target
   :statuscode 500: Internal Raiden node error

Querying Events
===============

Events are kept by the node. Once an event endpoint is queried the relevant events
from either the beginning of time or the given block are returned. Events are returned in a sorted list with the most recent events on the top of the list.

In Raiden we distinguish between two types of events: ``blockchain_events`` and ``raiden_events``.
``blockchain_events`` are events that are being emitted by the smart contracts.
``raiden_events`` are events happening in the Raiden nod. For now, it's being used for debugging purpose.

.. NOTE::
      All raiden event endpoints are for debugging only and might get removed in the future.

All events can be filtered down by providing the query string arguments ``from_block``
and/or ``to_block`` to query only a events from a limited range of blocks. The block number
argument needs to be in the range of 0 to UINT64_MAX. Any blocknumber outside this range will
be rejected.

.. http:get:: /api/(version)/events/network

   Query for token network creations.

   .. NOTE::
      The network registry used is the default registry. The default registry is
      preconfigured and can be edited from the raiden configuration file.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/events/network HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
        {
            args: {
                token_address: "0x2E2A012D28cC95ed6A254fe14501722925719e72",
                token_network_address: "0x398a45A94292E850932deD44F1db20cA494400db"
            },
            event: "TokenNetworkCreated",
            logIndex: 3,
            transactionIndex: 7,
            transactionHash: "0xf162f616f241679f954385c8a63450f554aa34a97dedf2eb5e7b19ef3c78d31a",
            address: "0xDfD10bAe9CCC5EBf11bc6309A0645eFe9f979584",
            blockHash: "0xb6b0fa7080293bf0649ce86e9bb6e13dbf92ca8ced52a550df8c790b67c84131",
            block_number: 3745593
        }, ...
      ]

   :statuscode 200: For successful query
   :statuscode 400: If the provided query string is malformed
   :statuscode 409: If the given block number argument is invalid
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/blockchain_events/tokens/(token_address)

   Query for all blockchain events happening on a token network.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/blockchain_events/tokens/0x0f114A1E9Db192502E7856309cc899952b3db1ED HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

    [
        {
            args: {
                channel_identifier: "0xce2283dd884aeec753d534968683193bdfb8f92d3e134a992a9b43ee0dd4a613",
                participant1: "0x3C46570896F3eC1323280Df466716d1076a7162B",
                participant2: "0x13AE1c7fb262be079d7850d435D75a9bFC141b8e",
                settle_timeout: 600
            },
            event: "ChannelOpened",
            logIndex: 6,
            transactionIndex: 10,
            transactionHash: "0x021d0cc04a1e2aa182b38c5d20396b1b3a5aa1a2da255c0fa006d67d0fd1f5d8",
            address: "0x7692624c0C43285D51c0DdDfb2A6388f5002762E",
            blockHash: "0x5249788b4d34b9f6104f33aa1d8b6dab254adc0c038501ca8e974acb46e75fa3",
            block_number: 3750320
        },
        {
            args: {
                channel_identifier: "0xcc89e8554f9031bf23d5b2cf1fc26d3cd3dbde4ebbcbf7248a51432d5bc8916c",
                participant1: "0x7A664079423fa25B87014EB53282F34c7AC7B87E",
                participant2: "0x000D91Cf263a11F9BfCeE3752E5B03FC1196CE98",
                settle_timeout: 500
            },
            event: "ChannelOpened",
            logIndex: 9,
            transactionIndex: 17,
            transactionHash: "0x60c7c4480b5d3d0d7f94f42ad70f77a2b44613b3eb001503272f758613893370",
            address: "0x7692624c0C43285D51c0DdDfb2A6388f5002762E",
            blockHash: "0xce6741d45439abfcf8a3af0dde480e9b2bf17a61a1bec52a99e946f5921c4278",
            block_number: 3750140
        }, ...
    ]

   :statuscode 200: For successful query
   :statuscode 400: If the provided query string is malformed
   :statuscode 404: If the token at the given token_address does not exist
   :statuscode 409: If the given block number or token_address arguments are invalid
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/blockchain_events/payment_networks/(token_address)/channels/(partner_address)

   Query for ``blockchain_events`` tied to all the channels which are part of the token network.
   If the partner_address is not provided it will show the events for all the channels.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /blockchain_events/payment_networks/0x0f114A1E9Db192502E7856309cc899952b3db1ED/channels/ HTTP/1.1
      Host: localhost:5001

  **Example Response**:

  .. sourcecode:: http

     HTTP/1.1 200 OK
     Content-Type: application/json

    [
        {
            args: {
                channel_identifier: "0xa152038763d73b05df7b036f477236b527ad14a249e4077fb4048d845226ac43",
                participant1_amount: 60,
                participant2_amount: 955
            },
            event: "ChannelSettled",
            logIndex: 3,
            transactionIndex: 2,
            transactionHash: "0x6460c83a8005b3c04179e4d63817d7c5877e0d3ed514a60b25cfd8368330d7f4",
            address: "0x7692624c0C43285D51c0DdDfb2A6388f5002762E",
            blockHash: "0x988abf5d672a9d6e07a2210ca5f4391bf9ef38e65896457f1bf95024d4f172f0",
            block_number: 3694882
        }, ...
    ]


  **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /blockchain_events/payment_networks/0x0f114A1E9Db192502E7856309cc899952b3db1ED/channels/0x82641569b2062B545431cF6D7F0A418582865ba7 HTTP/1.1
      Host: localhost:5001

  **Example Response**:

  .. sourcecode:: http

     HTTP/1.1 200 OK
     Content-Type: application/json

    [
        {
            args: {
                channel_identifier: "0xa152038763d73b05df7b036f477236b527ad14a249e4077fb4048d845226ac43",
                participant1: "0x82641569b2062B545431cF6D7F0A418582865ba7",
                participant2: "0x8A0cE8bDA200D64d858957080bf7eDDD3371135F",
                settle_timeout: 600
            },
            event: "ChannelOpened",
            logIndex: 1,
            transactionIndex: 1,
            transactionHash: "0x6c1ea37c2d401244e336863a2c7e149a2b364655b6423af472e48044878db107",
            address: "0x7692624c0C43285D51c0DdDfb2A6388f5002762E",
            blockHash: "0xcc88f89b3278b7abcb49eeabfe055df5de60449eac5876e77ebf0fcb7ab968f8",
            block_number: 3694177
        }, ...
    ]

  :statuscode 200: For successful query
  :statuscode 400: If the provided query string is malformed
  :statuscode 404: If the channel does not exist
  :statuscode 409: If the given block number argument is invalid
  :statuscode 500: Internal Raiden node error

.. http:get:: /api/1/payments/(token_address)/(target_address)

     Query the payment history. This includes successful (EventPaymentSentSuccess) and failed (EventPaymentSentFailed) sent payments as well as received payments (EventPaymentReceivedSuccess).
     ``token_address`` and ``target_address`` are optional and will filter the list of events accordingly.

    **Example Request**:

    .. http:example:: curl wget httpie python-requests

       GET /payments/0x0f114A1E9Db192502E7856309cc899952b3db1ED/0x82641569b2062B545431cF6D7F0A418582865ba7  HTTP/1.1
       Host: localhost:5001

    **Example Response**:

    .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

     [
         {
             block_number: 3694255,
             event: "EventPaymentReceivedSuccess",
             amount: 5,
             initiator: "0x82641569b2062B545431cF6D7F0A418582865ba7"
         },
         {
             block_number: 3694245,
             event: "EventPaymentSentSuccess",
             amount: 35,
             target: "0x82641569b2062B545431cF6D7F0A418582865ba7"
         },
         {
             block_number: 3694216,
             event: "EventPaymentSentSuccess",
             amount: 20,
             target: "0x82641569b2062B545431cF6D7F0A418582865ba7"
         }
     ]

  :statuscode 200: For successful query
  :statuscode 400: If the provided query string is malformed
  :statuscode 409: If the given block number or token_address arguments are invalid
  :statuscode 500: Internal Raiden node error


Now for the raiden events:

.. http:get:: /api/(version)/raiden_events/tokens/(token_address)

   Query for Raiden internal node events.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /raiden_events/tokens/0xb2eef045d5c05cfc9b351a59cc5c4597de6487e2 HTTP/1.1
      Host: localhost:5001

  **Example Response**:

  .. sourcecode:: http

     HTTP/1.1 200 OK
     Content-Type: application/json

    [{
        'block_number': 36,
        'event': 'SendLockedTransfer',
        'message_identifier': 17084435898865420397,
        'recipient': '0x636f37d785257d919931acff318f70fb7da4f903',
        'transfer': '<LockedTransferUnsignedState id:43 '
                      'token:0xb2eef045d5c05cfc9b351a59cc5c4597de6487e2 '
                      'balance_proof:<BalanceProofUnsignedState nonce:1 '
                      'transferred_amount:0 locked_amount:200 locksroot:e12a619f '
                      'token_network:edf18937 channel_identifier:1 chain_id: 337> '
                      'lock:<HashTimeLockState amount:200 expiration:56 '
                      'secrethash:8747cef6> '
                      'target:0x636f37d785257d919931acff318f70fb7da4f903>'
     },
     {
        'block_number': 36,
        'event': 'SendRevealSecret',
        'message_identifier': 9182020688704924936,
        'recipient': '0x636f37d785257d919931acff318f70fb7da4f903',
        'secret': '0xcefe6d325fc2b01f47d303417ddd14d788a31c0b078610b427a85b2141bc514d',
        'secrethash': '0x8747cef6a143f0bd123070ea75479f7e09a451a08ce731fb572211d8bda11b3a'
     },
     {
        'amount': 200,
        'block_number': 36,
        'event': 'EventPaymentSentSuccess',
        'identifier': 43,
        'payment_network_identifier': '0x41ac2632d8c233784783e50ec6678cdc43f74c76',
        'target': '0x636F37d785257D919931ACFf318F70fB7Da4f903',
        'token_network_identifier': '0xedf18937be4064dfbe3e307bd193e812b723ac6f'
     }, ...]

  :statuscode 200: For successful query
  :statuscode 400: If the provided query string is malformed
  :statuscode 404: If the token at the given token_address does not exist
  :statuscode 409: If the given block number or token_address arguments are invalid
  :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/raiden_events/payment_networks/(token_address)/channels/(partner_address)

   Query for Raiden internal node events.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /raiden_events/payment_networks/0x7150c717eb60978713f4ddaa288cf3101581cd81/channels/ HTTP/1.1
      Host: localhost:5001

  **Example Response**:

  .. sourcecode:: http

     HTTP/1.1 200 OK
     Content-Type: application/json

    [{
        'block_number': 36,
        'event': 'SendLockedTransfer',
        'message_identifier': 16700893459475179678,
        'recipient': '0x1d2cb001f807882c4a862731cbb77390e641a8fd',
        'transfer': '<LockedTransferUnsignedState id:42 '
                  'token:0x7150c717eb60978713f4ddaa288cf3101581cd81 '
                  'balance_proof:<BalanceProofUnsignedState nonce:1 '
                  'transferred_amount:0 locked_amount:200 locksroot:b407910b '
                  'token_network:b12596e5 channel_identifier:1 chain_id: 337> '
                  'lock:<HashTimeLockState amount:200 expiration:56 '
                  'secrethash:8ee5cb32> '
                  'target:0x1d2cb001f807882c4a862731cbb77390e641a8fd>'
     },
     {
        'block_number': 36,
        'event': 'SendRevealSecret',
        'message_identifier': 17638248769110067506,
        'recipient': '0x1d2cb001f807882c4a862731cbb77390e641a8fd',
        'secret': '0x211c0b2cef1541eda28e0b1f86391f19eb3519fccd2e643096d9066a8a992d10',
        'secrethash': '0x8ee5cb32c24203b9d62dd55359c3494f4a1694039fb0ce7c2c46bdf619b54c76'
     },
     {
        'amount': 200,
        'block_number': 36,
        'event': 'EventPaymentSentSuccess',
        'identifier': 42,
        'payment_network_identifier': '0xf6febb9ca9efab37e495612dff0e30964cbb2c15',
        'target': '0x1d2cB001f807882C4a862731CBB77390e641A8fD',
        'token_network_identifier': '0xb12596e59a7fa29c0f7c349261cd91148a496dc8'
     },
     {
        'block_number': 36,
        'event': 'EventUnlockSuccess',
        'identifier': 42,
        'secrethash': '0x8ee5cb32c24203b9d62dd55359c3494f4a1694039fb0ce7c2c46bdf619b54c76'
     },
     {
        'balance_proof': '<BalanceProofUnsignedState nonce:2 transferred_amount:200 '
                       'locked_amount:0 locksroot:00000000 token_network:b12596e5 '
                       'channel_identifier:1 chain_id: 337>',
        'block_number': 36,
        'event': 'SendBalanceProof',
        'message_identifier': 42,
        'payment_identifier': 5518212473974981549,
        'recipient': '0x1d2cb001f807882c4a862731cbb77390e641a8fd',
        'secret': '0x211c0b2cef1541eda28e0b1f86391f19eb3519fccd2e643096d9066a8a992d10',
        'token': '0x7150c717eb60978713f4ddaa288cf3101581cd81'
     }]


  :statuscode 200: For successful query
  :statuscode 400: If the provided query string is malformed
  :statuscode 404: If the token at the given token_address does not exist
  :statuscode 409: If the given token_address argument is invalid
  :statuscode 500: Internal Raiden node error
