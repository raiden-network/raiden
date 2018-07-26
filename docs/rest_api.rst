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

- ``balance`` should be an integer of the amount of the ``token_address`` token we have available for transferring.

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

Transfers
=========

.. http:post:: /api/(version)/transfers/(token_address)/(target_address)

   Initiate a transfer.

   The request will only return once the transfer either succeeded or failed. A transfer can fail due to the expiration of a lock, the target being offline, channels on the path to the target not having enough ``settle_timeout`` and ``reveal_timeout`` in order to allow the transfer to be propagated safely e.t.c

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/1/transfers/0x2a65Aca4D5fC5B5C859090a6c34d164135398226/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "amount": 200,
          "identifier": 42
      }

   :reqjson int amount: Amount to be transferred
   :reqjson int identifier: Identifier of the transfer (optional)

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

   :statuscode 200: Successful transfer
   :statuscode 400: If the provided json is in some way malformed
   :statuscode 402: If the transfer can't start due to insufficient balance
   :statuscode 408: If a timeout happened during the transfer
   :statuscode 409: If the address or the amount is invalid or if there is no path to the target
   :statuscode 500: Internal Raiden node error

Querying Events
===============

Events are kept by the node. Once an event endpoint is queried the relevant events
from either the beginning of time or the given block are returned. Events are returned in a sorted list with the most recent events on the top of the list.

Events are queried by two different endpoints depending on whether they are related
to a specific channel or not.

All events can be filtered down by providing the query string arguments ``from_block``
and/or ``to_block`` to query only a events from a limited range of blocks. The block number
argument needs to be in the range of 0 to UINT64_MAX. Any blocknumber outside this range will
be rejected.

.. http:get:: /api/(version)/events/network

   Query for registry network events.

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
              "event_type": "TokenAdded",
              "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
              "channel_manager_address": "0xC0ea08A2d404d3172d2AdD29A45be56dA40e2949"
          }, {
              "event_type": "TokenAdded",
              "token_address": "0x91337A300e0361BDDb2e377DD4e88CCB7796663D",
              "channel_manager_address": "0xC0ea08A2d404d3172d2AdD29A45be56dA40e2949"
          }
      ]

   :statuscode 200: For successful query
   :statuscode 400: If the provided query string is malformed
   :statuscode 409: If the given block number argument is invalid
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/events/tokens/(token_address)

   Query for all new channels opened for a token

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/events/tokens/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
          {
              "event_type": "ChannelNew",
              "settle_timeout": 500,
              "netting_channel": "0xC0ea08A2d404d3172d2AdD29A45be56dA40e2949",
              "participant1": "0x4894A542053248E0c504e3dEF2048c08f73E1CA6",
              "participant2": "0x356857Cd22CBEFccDa4e96AF13b408623473237A"
          }, {
              "event_type": "ChannelNew",
              "settle_timeout": 1500,
              "netting_channel": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
              "participant1": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
              "participant2": "0xc7262f1447FCB2f75AB14B2A28DeEd6006eEA95B"
          }
      ]

   :statuscode 200: For successful query
   :statuscode 400: If the provided query string is malformed
   :statuscode 404: If the token does not exist
   :statuscode 409: If the given block number argument is invalid
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/events/channels/(channel_address)

   Query for events tied to a specific channel.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/1/events/channels/0x2a65Aca4D5fC5B5C859090a6c34d164135398226?from_block=1337 HTTP/1.1
      Host: localhost:5001

  **Example Response**:

  .. sourcecode:: http

     HTTP/1.1 200 OK
     Content-Type: application/json

     [
         {
             "event_type": "ChannelNewBalance",
             "participant": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
             "balance": 150000,
             "block_number": 54388
         }, {
             "event_type": "TransferUpdated",
             "token_address": "0x91337A300e0361BDDb2e377DD4e88CCB7796663D",
             "channel_manager_address": "0xC0ea08A2d404d3172d2AdD29A45be56dA40e2949"
         }, {
             "event_type": "EventTransferSentSuccess",
             "identifier": 14909067296492875713,
             "block_number": 2226,
             "amount": 7,
             "target": "0xc7262f1447FCB2f75AB14B2A28DeEd6006eEA95B"
         }
     ]

  :statuscode 200: For successful query
  :statuscode 400: If the provided query string is malformed
  :statuscode 404: If the channel does not exist
  :statuscode 409: If the given block number argument is invalid
  :statuscode 500: Internal Raiden node error
