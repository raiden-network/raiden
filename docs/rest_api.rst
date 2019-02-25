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
       "channel_identifier": 21,
       "token_network_identifier": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226",
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
       "balance": 25000000,
       "total_deposit": 35000000,
       "state": "opened",
       "settle_timeout": 500,
       "reveal_timeout": 40
    }



A channel object consists of a

- ``channel_identifier`` should be an ``integer`` containing the identifier of the
  channel.

- ``partner_address`` should be a ``string`` containing the EIP55-encoded address of the
  partner with whom we have opened a channel.

- ``token_address`` should be a ``string`` containing the EIP55-encoded address of the
  token we are trading in the channel.

- ``token_network_identifier`` should be a ``string`` containing the EIP55-encoded address of the
  token network the channel is part of.

- ``balance`` should be an integer of the amount of the ``token_address`` token we have available for payments.

- ``total_deposit`` should be an integer of the amount of the ``token_address`` token we have deposited into the contract for this channel.

- ``state`` should be the current state of the channel represented by a string.
  Possible value are:
  - ``'opened'``: The channel is open and tokens are tradeable
  - ``'closed'``: The channel has been closed by a participant
  - ``'settled'``: The channel has been closed by a participant and also settled.

- ``'settle_timeout'``: The number of blocks that are required to be mined from the time that ``close()`` is called until the channel can be settled with a call to ``settle()``.

- ``'reveal_timeout'``: The maximum number of blocks allowed between the setting of a hashlock and the revealing of the related secret.

Event Object
==============

Channel events are encoded as json objects with the event arguments as attributes
of the dictionary, with one difference. The ``event_type`` and the ``block_number`` are also added for all events to easily distinguish between events.

Errors
======

For any non-successful http status code, e.g. :http:statuscode:`409` or :http:statuscode:`400` there will be an accompanying ``errors`` field in the response json which you can check for more information on what went wrong with your request.
However, when Raiden fails to process the incoming request and raises an exception, the returned http status code will be :http:statuscode:`500`. The caveat of this is that the response body will be just a string message which says "Internal server error".
This is because we rely on our underlying stack to handle this while we take care of shutting down the API server preventing further incoming requests caused the exception in the first place from tampering with a state that was corrupted.
In any way, we consider :http:statuscode:`500` errors as bugs in the Raiden client. If you encounter such errors, please report the bug `here <https://github.com/raiden-network/raiden/issues/new?template=bug_report.md>`_.

Endpoints
***********

Following are the available API endpoints with which you can interact with Raiden.

Querying Information About Your Raiden Node
===============================================

.. http:get:: /api/(version)/address

   Query your address. When raiden starts, you choose an ethereum address which will also be your raiden address.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/address HTTP/1.1
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
.. note::
   For the Raiden Red Eyes release, it will not be possible to register more than one token, due to security reasons in order to minimise possible loss of funds in the case of bugs. The one token that will be registered is `W-ETH <https://weth.io/>`_.

.. http:put:: /api/(version)/tokens/(token_address)

   Registers a token. If a token is not registered yet (i.e.: A token network for that token does not exist in the registry), we need to register it by deploying a token network contract for that token.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      PUT /api/v1/tokens/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 201 CREATED
      Content-Type: application/json

      {
          "token_network_address": "0xC4F8393fb7971E8B299bC1b302F85BfFB3a1275a"
      }

   :statuscode 201: A token network for the token has been successfully created.
   :statuscode 402: Insufficient ETH to pay for the gas of the register on-chain transaction
   :statuscode 404: The given token address is invalid.
   :statuscode 409:
    - The token was already registered before, or
    - The registering transaction failed.
   :statuscode 501: Registering a token only works on testnet temporarily. On mainnet this error is returned.
   :resjson address token_network_address: The deployed token networks address.

Querying Information About Channels and Tokens
==============================================

.. http:get:: /api/(version)/channels

   Get a list of all unsettled channels.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/channels HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
          {
              "token_network_identifier": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
              "channel_identifier": 20,
              "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
              "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
              "balance": 25000000,
              "total_deposit": 35000000,
              "state": "opened",
              "settle_timeout": 100,
              "reveal_timeout": 30
          }
      ]

   :statuscode 200: Successful query
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/channels/(token_address)

   Get a list of all unsettled channels for the given token address.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
          {
              "token_network_identifier": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
              "channel_identifier": 20,
              "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
              "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
              "balance": 25000000,
              "total_deposit": 35000000,
              "state": "opened",
              "settle_timeout": 100,
              "reveal_timeout": 30
          }
      ]

   :statuscode 200: Successful query
   :statuscode 404: The given token address is not a valid eip55-encoded Ethereum address
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/channels/(token_address)/(partner_address)

   Query information about one of your channels. The channel is specified by the address of the token and the partner's address.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "token_network_identifier": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
          "channel_identifier": 20,
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": 25000000,
          "total_deposit": 35000000,
          "state": "opened",
          "settle_timeout": 100,
          "reveal_timeout": 30
      }

   :statuscode 200: Successful query
   :statuscode 404:
    - The given token and / or partner addresses are not valid eip55-encoded Ethereum addresses, or
    - The channel does not exist
   :statuscode 500: Internal Raiden node error

.. http:get:: /api/(version)/tokens

   Returns a list of addresses of all registered tokens.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/tokens HTTP/1.1
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

.. http:get:: /api/(version)/tokens/(token_address)

   Returns the address of the corresponding token network for the given token, if the token is registered.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/tokens/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      "0x61bB630D3B2e8eda0FC1d50F9f958eC02e3969F6"

   :statuscode 200: Successful query
   :statuscode 404: No token network found for the provided token address

.. http:get:: /api/(version)/tokens/(token_address)/partners

   Returns a list of all partners with whom you have non-settled channels for a certain token.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/tokens/0x61bB630D3B2e8eda0FC1d50F9f958eC02e3969F6/partners HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
         {
             "partner_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
             "channel": "/api/<version>/channels/0x61C808D82A3Ac53231750daDc13c777b59310bD9/0x2a65aca4d5fc5b5c859090a6c34d164135398226"
         }
      ]

   :statuscode 200: Successful query
   :statuscode 302: If the user accesses the channel link endpoint
   :statuscode 404:
    - The token does not exist
    - The token address is not a valid eip55-encoded Ethereum address
   :statuscode 500: Internal Raiden node error
   :resjsonarr address partner_address: The partner we have a channel with
   :resjsonarr link channel: A link to the channel resource

.. http:get:: /api/(version)/pending_transfers

   Returns a list of all transfers that have not been completed yet.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/pending_transfers HTTP/1.1
      Host: localhost:5001

   See below for an example response.

.. http:get:: /api/(version)/pending_transfers/(token_address)

   Like above, but limited to pending transfers of the specified token.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/pending_transfers/0xd0A1E359811322d97991E03f863a0C30C2cF029C HTTP/1.1
      Host: localhost:5001

   See below for an example response.

.. http:get:: /api/(version)/pending_transfers/(token_address)/(partner_address)

   Like above, but limited to the specified channel.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/pending_transfers/0xd0A1E359811322d97991E03f863a0C30C2cF029C/0x2c4b0Bdac486d492E3cD701F4cA87e480AE4C685 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
         {
            "channel_identifier": "255",
            "initiator": "0x5E1a3601538f94c9e6D2B40F7589030ac5885FE7",
            "locked_amount": "119",
            "payment_identifier": "1",
            "role": "initiator",
            "target": "0x00AF5cBfc8dC76cd599aF623E60F763228906F3E",
            "token_address": "0xd0A1E359811322d97991E03f863a0C30C2cF029C",
            "token_network_identifier": "0x111157460c0F41EfD9107239B7864c062aA8B978",
            "transferred_amount": "331"
         }

      ]

   :statuscode 200: Successful query
   :statuscode 404: The queried channel or token was not found
   :statuscode 500: Internal Raiden node error
   :resjsonarr string role: One of "initiator", "mediator" and "target"




Channel Management
==================

.. http:put:: /api/(version)/channels

   Opens (i. e. creates) a channel.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      PUT /api/v1/channels HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "total_deposit": 35000000,
          "settle_timeout": 500
      }

   :reqjson address partner_address: The partner we want to open a channel with.
   :reqjson address token_address: The token we want to be used in the channel.
   :reqjson int total_deposit: Total amount of tokens to be deposited to the channel
   :reqjson int settle_timeout: The amount of blocks that the settle timeout should have.

   The request's payload is a channel object; since it is a new channel, its ``channel_address``
   and ``status`` fields will be ignored and can be omitted.

   The request to the endpoint will later return the fully created channel object.

   .. note::
      For the Raiden Red Eyes release the maximum deposit per node in a channel is limited to 0.075 worth of `W-ETH <https://weth.io/>`_. This means that the maximum amount of tokens in a channel is limited to 0.15 worth of W-ETH. This is done to mitigate risk since the Red Eyes release is an alpha testing version on the mainnet.


   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 201 CREATED
      Content-Type: application/json

      {
          "token_network_identifier": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
          "channel_identifier": 20,
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": 25000000,
          "total_deposit": 35000000,
          "state": "opened",
          "settle_timeout": 500,
          "reveal_timeout": 30
      }

   :statuscode 201: Channel created successfully
   :statuscode 400: Provided JSON is in some way malformed
   :statuscode 402: Insufficient ETH to pay for the gas of the channel open on-chain transaction
   :statuscode 408: Deposit event was not read in time by the Ethereum node
   :statuscode 409: Invalid input, e. g. too low a settle timeout
   :statuscode 500: Internal Raiden node error

.. http:patch:: /api/(version)/channels/(token_address)/(partner_address)

   This request is used to close a channel or to increase the deposit in it.

   **Example Request (close channel)**:

   .. http:example:: curl wget httpie python-requests

      PATCH /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "state": "closed"
      }

   **Example Request (increase deposit)**:

   .. http:example:: curl wget httpie python-requests

      PATCH /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "total_deposit": 100
      }

   :reqjson string state: Desired new state; the only valid choice is ``"closed"``
   :reqjson int total_deposit: The increased total deposit

   .. note::
      For the Raiden Red Eyes release the maximum deposit per node in a channel is limited to 0.075 worth of `W-ETH <https://weth.io/>`_. This means that the maximum amount of tokens in a channel is limited to 0.15 worth of W-ETH. This is done to mitigate risk since the Red Eyes release is an alpha testing version on the mainnet.

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "token_network_identifier": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
          "channel_identifier": 20,
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": 25000000,
          "total_deposit": 35000000,
          "state": "closed",
          "settle_timeout": 500,
          "reveal_timeout": 30
      }

   :statuscode 200: Success
   :statuscode 400:
    - The provided JSON is in some way malformed, or
    - there is nothing to do since neither ``state`` nor ``total_deposit`` have been given, or
    - the value of ``state`` is not a valid channel state.
   :statuscode 402: Insufficient balance to do a deposit, or insufficient ETH to pay for the gas of the on-chain transaction
   :statuscode 404: The given token and / or partner addresses are not valid eip55-encoded Ethereum addresses
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

      GET /api/v1/connections HTTP/1.1
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

   :statuscode 200: For a successful query
   :statuscode 500: Internal Raiden node error
   :resjsonarr int funds: Funds from last connect request
   :resjsonarr int sum_deposits: Sum of deposits of all currently open channels
   :resjsonarr int channels: Number of channels currently open for that token

.. http:put:: /api/(version)/connections/(token_address)

   Automatically join a token network. The request will only return once all blockchain calls for
   opening and/or depositing to a channel have completed.

   The request's payload has ``initial_channel_target`` and ``joinable_funds_target`` as optional arguments. If not provided they default to ``initial_channel_target = 3`` and ``joinable_funds_target = 0.4``.

   If the ``initial_channel_target`` is bigger than the current number of participants of the token network then the funds will still be split according to the ``initial_channel_target`` but the number of channels made will be equal to the number of participants in the network. So eventually you will end up with less channels, but each channel will have the expected number of funds allocated to it. The remaining channels will be opened once more peers become available.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      PUT /api/v1/connections/0x2a65Aca4D5fC5B5C859090a6c34d164135398226 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "funds": 1337
      }

   :statuscode 204: For a successful connection creation.
   :statuscode 402: If any of the channel deposits fail due to insufficient ETH balance to pay for the gas of the on-chain transactions.
   :statuscode 404: The given token address is not a valid eip55-encoded Ethereum address
   :statuscode 408: If a timeout happened during any of the transactions.
   :statuscode 409: If any of the provided input to the call is invalid.
   :statuscode 500: Internal Raiden node error.
   :reqjson int funds: Amount of funding you want to put into the network.
   :reqjson int initial_channel_target: Number of channels to open proactively.
   :reqjson float joinable_funds_target: Fraction of funds that will be used to join channels opened by other participants.

   .. note::
      Currently, the API calls are blocking. This means that in the case of long running calls like ``join``, if other calls to ``join`` are made concurrently, they will block too and wait for the first call to finish. If an API call is currently being processed by Raiden, all pending calls will be queued and processed with their passed API call argument.

.. http:delete:: /api/(version)/connections/(token_address)

   Leave a token network. The request will only return once all blockchain calls for closing/settling a channel have completed.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      DELETE /api/v1/connections/0x2a65Aca4D5fC5B5C859090a6c34d164135398226 HTTP/1.1
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
   :statuscode 404: The given token address is not a valid eip55-encoded Ethereum address
   :statuscode 500: Internal Raiden node error

   .. note::
      Currently, the API calls are blocking. This means that in the case of long running calls like ``leave``, if an API call is currently being processed by Raiden, all pending calls will be queued and processed with their passed API call argument.

Payments
========

.. http:post:: /api/(version)/payments/(token_address)/(target_address)

   Initiate a payment.

   The request will only return once the payment either succeeded or failed. A payment can fail due to the expiration of a lock, the target being offline, channels on the path to the target not having enough ``settle_timeout`` and ``reveal_timeout`` in order to allow the payment to be propagated safely, not enough funds etc.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/v1/payments/0x2a65Aca4D5fC5B5C859090a6c34d164135398226/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
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
   :statuscode 404: The given token and / or target addresses are not valid eip55-encoded Ethereum addresses
   :statuscode 408: If a timeout happened during the payment
   :statuscode 409: If the address or the amount is invalid or if there is no path to the target, or if the identifier is already in use for a different payment.
   :statuscode 500: Internal Raiden node error

Querying Events
===============

Events are kept by the node. A normal user should only care about the events exposed for payments. Those events show if a payment failed or if it was successful.

For ``raiden_events`` you can provide a ``limit`` and an ``offset`` number which would define the limit of results to return and the offset from which to return results respectively.

``raiden_events`` contain a timestamp field, ``log_time``, indicating when they were written to the write-ahead log.
The format of ``log_time`` is ISO8601 with milliseconds.



.. http:get:: /api/v1/payments/(token_address)/(target_address)

     Query the payment history. This includes successful (EventPaymentSentSuccess) and failed (EventPaymentSentFailed) sent payments as well as received payments (EventPaymentReceivedSuccess).
     ``token_address`` and ``target_address`` are optional and will filter the list of events accordingly.

    **Example Request**:

    .. http:example:: curl wget httpie python-requests

       GET /api/v1/payments/0x0f114A1E9Db192502E7856309cc899952b3db1ED/0x82641569b2062B545431cF6D7F0A418582865ba7  HTTP/1.1
       Host: localhost:5001

    **Example Response**:

    .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
          {
              "event": "EventPaymentReceivedSuccess",
              "amount": 5,
              "initiator": "0x82641569b2062B545431cF6D7F0A418582865ba7",
              "identifier": 1,
              "log_time": "2018-10-30T07:03:52.193"
          },
          {
              "event": "EventPaymentSentSuccess",
              "amount": 35,
              "target": "0x82641569b2062B545431cF6D7F0A418582865ba7",
              "identifier": 2,
              "log_time": "2018-10-30T07:04:22.293"
          },
          {
              "event": "EventPaymentSentSuccess",
              "amount": 20,
              "target": "0x82641569b2062B545431cF6D7F0A418582865ba7"
              "identifier": 3,
              "log_time": "2018-10-30T07:10:13.122"
          }
      ]

  :statuscode 200: For successful query
  :statuscode 404: The given token and / or partner addresses are not valid eip55-encoded Ethereum addresses
  :statuscode 409: If the given block number or token_address arguments are invalid
  :statuscode 500: Internal Raiden node error
