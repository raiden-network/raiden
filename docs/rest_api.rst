Raiden's API Documentation
##########################

.. toctree::
   :maxdepth: 2

Introduction
*************
The Raiden API is organized around REST and has resource-oriented URL endpoints that accept and return JSON-encoded responses. 
The Raiden API uses standard HTTP response codes and verbs.
The Raiden RESTful API endpoints correspond to the interactions allowed by a Raiden node. 
The URL path always contains the API version as an integer. 
All endpoints start with ``/api/<version>/``



JSON Object Encoding
********************

The objects that are sent to and received from the API are JSON-encoded. Following are the common objects used in the API.

Channel Object
===============
::

    {
       "channel_identifier": "21",
       "token_network_address": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226",
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
       "balance": "25000000",
       "total_deposit": "35000000",
       "total_withdraw": "15000000",
       "state": "opened",
       "settle_timeout": "500",
       "reveal_timeout": "50"
    }



A channel object consists of a

- ``channel_identifier``: string containing the identifier of the
  channel.

- ``partner_address``: string containing the EIP55-encoded address of the
  partner with whom we have opened a channel.

- ``token_address``: string containing the EIP55-encoded address of the
  token we are trading in the channel.

- ``token_network_address``: string containing the EIP55-encoded address of the
  token network the channel is part of.

- ``balance``: string of the amount of the ``token_address`` token we have available for payments.

- ``total_deposit``: string of the amount of the ``token_address`` token we have deposited into the contract for this channel.

- ``total_withdraw``: string of the amount of the ``token_address`` token we have withdrawn from the channel on-chain.

- ``state``: current state of the channel represented by a string. Possible values are:

   - ``"opened"``: The channel is open and tokens are tradeable
   - ``"closed"``: The channel has been closed by a participant
   - ``"settled"``: The channel has been closed by a participant and also settled.

- ``settle_timeout``: The number of blocks that are required to be mined from the time that ``close()`` is called until the channel can be settled with a call to ``settle()``.

- ``reveal_timeout``: The maximum number of blocks allowed between the setting of a hashlock and the revealing of the related secret.


Errors
======

For any non-successful http status code, e.g. :http:statuscode:`409` or :http:statuscode:`400` there will be an accompanying ``errors`` field in the response json which you can check for more information on what went wrong with your request.
However, when Raiden fails to process the incoming request and raises an exception, the returned http status code will be :http:statuscode:`500`. The caveat of this is that the response body will be just a string message which says "Internal server error".
This is because we rely on our underlying stack to handle this while we take care of shutting down the API server preventing further incoming requests caused the exception in the first place from tampering with a state that was corrupted.
In any way, we consider :http:statuscode:`500` errors as bugs in the Raiden client. If you encounter such errors, please report the bug `here <https://github.com/raiden-network/raiden/issues/new?template=bug_report.md>`_.

.. _api_endpoints:

Resources
*********

All objects that are sent and received from the Raiden API are JSON encoded.
The following outlines each of the Raiden API endpoints.

.. _api_address:

Address
=======

.. http:get:: /api/(version)/address

   Queries the Ethereum address you choose when starting Raiden. 
   A Raiden node is up and running correctly if the response returns that same address.

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


Version
=======

.. http:get:: /api/(version)/version

   You can query the version endpoint to see which version of Raiden you're currently running.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/version HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "version": "0.100.5a1.dev157+geb2af878d"
      }


Status
======

.. http:get:: /api/(version)/status

   Query the node status. Possible answers are:

   - ``"ready"``: The node is listening on its API endpoints.

   - ``"syncing"``: The node is still in the initial sync. Number of blocks to sync will also be given.

   - ``"unavailable"``: The node is unavailable for some other reason.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/status HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
         "status": "syncing",
         "blocks_to_sync": "130452"
      }

   :statuscode 200: Successful query
   :statuscode 500: Internal Raiden error


.. _api_settings:

Settings
========

.. http:get:: /api/(version)/settings

   Queries the settings of your Raiden node. 
   At the moment only the URL of the pathfinding service is returned. 
   The endpoint will provide more settings in the future.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/settings HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "pathfinding_service_address": "https://pfs.transport04.raiden.network"
      }


Contracts
=========

.. http:get:: /api/(version)/contracts

   By querying the contracts endpoint you can check which on-chain smart contracts are used.
   Returns the addresses of the smart contracts in use.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/contracts HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
         "contracts_version": "0.37.1",
         "monitoring_service_address": "0x20e8e5181000e60799A523a2023d630868f378Fd",
         "one_to_n_address": "0xA514Da2418576CeC4070C82996f30532dDa99706",
         "secret_registry_address": "0x9fC80eb1939d8147aB90BAC01AD585f3a71BeE7e",
         "service_registry_address": "0x3bc9C8d34f5714327095358668fD436D7c457C6C",
         "token_network_registry_address": "0x5a5CF4A63022F61F1506D1A2398490c2e8dfbb98",
         "user_deposit_address": "0x0794F09913AA8C77C8c5bdd1Ec4Bb51759Ee0cC5"
      }


Tokens
======

The tokens endpoints are used for registering new tokens and querying information about already registered tokens.

.. note::
   For the Alderaan release two tokens are registered, DAI and WETH.

**Information about Tokens**

.. _api_tokens:

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
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.

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
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.

.. http:get:: /api/(version)/tokens/(token_address)/partners

   Returns a list of all partner nodes with unsettled channels for a specific token.

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
      - The token address is not a valid EIP55-encoded Ethereum address
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.
   :resjsonarr address partner_address: The partner we have a channel with
   :resjsonarr link channel: A link to the channel resource
   

**Register a Token**

.. warning::
   For the Alderaan release it is not be possible to register more than two tokens, due to security reasons in order to minimise possible loss of funds in the case of bugs. 
   The two token that are registered are DAI and WETH.

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
   :statuscode 402: Insufficient ETH to pay for the gas of the register on-chain transaction.
   :statuscode 403: Maximum of allowed token networks reached. No new token networks can be registered.
   :statuscode 404: The given token address is invalid.
   :statuscode 409:
    - The token was already registered before, or
    - The registering transaction failed.
   :statuscode 501: Registering a token only works on testnet temporarily. On mainnet this error is returned.
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.
   :resjson address token_network_address: The deployed token networks address.


Channels
========

The channels endpoints allow you to open channels with other Raiden nodes as well as closing channels, querying them for information and making deposits or withdrawals.

.. warning::
   The maximum deposits per token and node for the Alderaan release are:

   **DAI**: The deposit limit is 1000 worth of DAI per channel participant making the maximum amount of DAI 2000 per channel.
   
   **WETH**: The deposit limit is 4.683 worth of WETH per channel participant making the maximum amount of WETH 9.366 per channel.


**Information about Channels**

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
              "token_network_address": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
              "channel_identifier": "20",
              "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
              "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
              "balance": "25000000",
              "total_deposit": "35000000",
              "total_withdraw": "5000000",
              "state": "opened",
              "settle_timeout": "500",
              "reveal_timeout": "50"
          }
      ]

   :statuscode 200: Successful query
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.

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
              "token_network_address": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
              "channel_identifier": "20",
              "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
              "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
              "balance": "25000000",
              "total_deposit": "35000000",
              "total_withdraw": "5000000",
              "state": "opened",
              "settle_timeout": "500",
              "reveal_timeout": "50"
          }
      ]

   :statuscode 200: Successful query
   :statuscode 404: The given token address is not a valid EIP55-encoded Ethereum address
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.

.. _api_channel_info:

.. http:get:: /api/(version)/channels/(token_address)/(partner_address)

   Query information about one of your channels. 
   The channel is specified by the address of a token and the address of the partner node which the channel is opened with.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "token_network_address": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
          "channel_identifier": "20",
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": "25000000",
          "total_deposit": "35000000",
          "total_withdraw": "5000000",
          "state": "opened",
          "settle_timeout": "500",
          "reveal_timeout": "50"
      }

   :statuscode 200: Successful query
   :statuscode 404:
    - The given token and / or partner addresses are not valid EIP55-encoded Ethereum addresses, or
    - The channel does not exist
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.


.. _api_open_channel:

**Create a Channel**

.. http:put:: /api/(version)/channels

   The request will open a channel and return the newly created channel object.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      PUT /api/v1/channels HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "total_deposit": "35000000",
          "settle_timeout": "500",
          "reveal_timeout": "50"
      }

   :reqjson address partner_address: Address of the partner node with whom we're opening the channel.
   :reqjson address token_address: Address of the token to be used in the channel.
   :reqjson string total_deposit: Amount of tokens to be deposited into the channel.
   :reqjson string settle_timeout: The number of blocks after which a channel can be settled.
   :reqjson string reveal_timeout: The number of blocks that are allowed between setting a hashlock and the revealing of the related secret.


   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 201 CREATED
      Content-Type: application/json

      {
          "token_network_address": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
          "channel_identifier": "20",
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": "25000000",
          "total_deposit": "35000000",
          "total_withdraw": "0",
          "state": "opened",
          "settle_timeout": "500",
          "reveal_timeout": "50"
      }

   :statuscode 201: Channel created successfully
   :statuscode 400: Provided JSON is in some way malformed
   :statuscode 402: Insufficient ETH to pay for the gas of the channel open on-chain transaction
   :statuscode 409: Invalid input, e. g. too low a settle timeout
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.


**Modify a Channel**

.. http:patch:: /api/(version)/channels/(token_address)/(partner_address)

   This request is used to close a channel, to increase the deposit in it, to withdraw tokens from it or to update its reveal timeout.
   The channel is specified by the address of a token and the address of the partner node which the channel is opened with.

   .. _api_close_channel:

   **Close Channel Example Request**:

   .. http:example:: curl wget httpie python-requests

      PATCH /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "state": "closed"
      }

   :reqjson string state: Can only be set to ``"closed"``

   .. _api_increase_deposit:

   **Increase Deposit Example Request**:

   .. http:example:: curl wget httpie python-requests

      PATCH /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "total_deposit": "100"
      }

   :reqjson string total_deposit: The increased total deposit

   .. _api_withdraw:

   **Withdraw Tokens Example Request**:

   .. http:example:: curl wget httpie python-requests

      PATCH /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "total_withdraw": "100"
      }

   :reqjson string total_withdraw: The increased total withdraw

   **Update Reveal Timeout Example Request**:

   .. http:example:: curl wget httpie python-requests

      PATCH /api/v1/channels/0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "reveal_timeout": "50"
      }

   :reqjson string reveal_timeout: The new reveal timeout value

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "token_network_address": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
          "channel_identifier": "20",
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "balance": "25000000",
          "total_deposit": "35000000",
          "total_withdraw": "5000000",
          "state": "closed",
          "settle_timeout": "500",
          "reveal_timeout": "50"
      }

   :statuscode 200: Success
   :statuscode 400:
    - The provided JSON is in some way malformed, or
    - there is nothing to do since none of ``state``, ``total_deposit`` or ``total_withdraw`` have been given, or
    - the value of ``state`` is not a valid channel state.
   :statuscode 402: Insufficient balance to do a deposit, or insufficient ETH to pay for the gas of the on-chain transaction
   :statuscode 404: The given token and / or partner addresses are not valid EIP55-encoded Ethereum addresses
   :statuscode 409:
    - Provided channel does not exist or
    - ``state``, ``total_deposit`` and ``total_withdraw`` have been attempted to update in the same request or
    - attempt to deposit token amount lower than on-chain balance of the channel or
    - attempt to deposit more tokens than the testing limit
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.


.. _Payments:

Payments
========

The payment endpoint is used for transferring tokens to another node. 
You can send the desired amount of tokens by providing the address of the token and the address of the receiving node.
Besides you can query all payments that you sent or received.


**Query the Payment History**

.. _api_list_payments:

.. http:get:: /api/(version)/payments/(token_address)/(partner_address)

   When querying the payment history the response will include:

   * "EventPaymentSentSuccess" for successful payments
   * "EventPaymentSentFailed" for failed payments
   * "EventPaymentReceivedSuccess" for received payments

   ``token_address`` and ``partner_address`` are optional and will filter the list of events accordingly.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/payments/0x0f114A1E9Db192502E7856309cc899952b3db1ED/0x82641569b2062B545431cF6D7F0A418582865ba7  HTTP/1.1
      Host: localhost:5001
   
   :query int limit: Limits the payment history result to the specified amount 
   :query int offset: Offsets the payment history result by the specified amount


   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
         {
            "event": "EventPaymentSentSuccess",
            "amount": "20",
            "target": "0x82641569b2062B545431cF6D7F0A418582865ba7",
            "identifier": "3",
            "log_time": "2018-10-30T07:10:13.122",
            "token_address": "0x62083c80353Df771426D209eF578619EE68D5C7A"
         },
         {
            "target": "0x82641569b2062B545431cF6D7F0A418582865ba7",
            "event": "EventPaymentSentFailed",
            "log_time": "2018-10-30T07:04:22.293",
            "reason": "there is no route available",
            "token_address": "0x62083c80353Df771426D209eF578619EE68D5C7A"
         },
         {
            "event": "EventPaymentReceivedSuccess",
            "amount": "5",
            "initiator": "0x82641569b2062B545431cF6D7F0A418582865ba7",
            "identifier": "1",
            "log_time": "2018-10-30T07:03:52.193",
            "token_address": "0x62083c80353Df771426D209eF578619EE68D5C7A"
         }
      ]

   :statuscode 200: For successful query
   :statuscode 404: The given token and / or partner addresses are not valid EIP55-encoded Ethereum addresses
   :statuscode 409: If the given block number or token_address arguments are invalid
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.
   :resjsonarr string event: One of "EventPaymentSentSuccess", "EventPaymentSentFailed" and "EventPaymentReceivedSuccess".
   :resjsonarr string amount: Token amount of the payment.
   :resjsonarr string target: Address of the node which received the payment.
   :resjsonarr string initiator: Address of the node which initiated the payment.
   :resjsonarr string identifier: Identifier of the payment.
   :resjsonarr string log_time: Time when the payment event was written to the write-ahead log. The format of ``log_time`` is ISO8601 with milliseconds.
   :resjsonarr string token_address: Address of token that was transferred.
   :resjsonarr string reason: Gives an explanation why a payment failed.


**Initiate a Payment**

.. _api_init_payment:

.. http:post:: /api/(version)/payments/(token_address)/(target_address)

   The request will only return once the payment either succeeds or fails.

   .. note::
      A payment can fail due to:

      * The secret for opening the hashlock not being revealed in time and the lock expires
      * The target node being offline
      * The channels leading to the target node not having enough ``settle_timeout`` and ``reveal_timeout``
      * The funds not being enough

   
   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/v1/payments/0x2a65Aca4D5fC5B5C859090a6c34d164135398226/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "amount": "200",
          "identifier": "42"
      }

   :reqjson string amount: Amount to be sent to the target
   :reqjson string identifier: Identifier of the payment (optional)
   :reqjson string lock_timeout: lock timeout, in blocks, to be used with the payment. Default is 2 * channel's reveal_timeout, Value must be greater than channel's reveal_timeout (optional)


   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "initiator_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "target_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226",
          "amount": "200",
          "identifier": "42",
          "secret": "0x4c7b2eae8bbed5bde529fda2dcb092fddee3cc89c89c8d4c747ec4e570b05f66",
          "secret_hash": "0x1f67db95d7bf4c8269f69d55831e627005a23bfc199744b7ab9abcb1c12353bd"
      }

   :statuscode 200: Successful payment
   :statuscode 400: The provided json is in some way malformed
   :statuscode 402: The payment can't start due to insufficient balance
   :statuscode 404: The given token and / or target addresses are not valid EIP55-encoded Ethereum addresses
   :statuscode 409: The address or the amount is invalid, or there is no path to the target, or the identifier is already in use for a different payment.
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.

   .. note::
      This endpoint will return as soon the initiator has unlocked the payment(i.e Unlock message is sent).
      However, this does not necessarily mean that querying the balance from the target node, immediately after
      the initiator returns, will return the new balance amount due to the fact that the target might not have received or processed the unlock.
  


User Deposit
============

For paying the :doc:`Raiden Services <raiden_services>` it is necessary to have RDN (Raiden Network Tokens) in the User Deposit Contract (UDC). 
This endpoint can be used to deposit to and withdraw from the UDC.


**Deposit**

.. http:post:: /api/(version)/user_deposit

   Deposit RDN tokens to the UDC.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/v1/user_deposit HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "total_deposit": "200000"
      }

   :reqjson string total_deposit: The total deposit token amount. Should be the sum of the current value and the desired deposit.

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
         "transaction_hash": "0xc5988c93c07cf1579e73d39ee2a3d6e948d959d11015465a77817e5239165170"
      }

   :statuscode 200: Deposit was successful
   :statuscode 400: The provided JSON is in some way malformed
   :statuscode 402: Insufficient balance to do a deposit or insufficient ETH to pay for the gas of the on-chain transaction
   :statuscode 404: No UDC is configured on the Raiden node
   :statuscode 409: The provided ``total_deposit`` is not higher than the previous ``total_deposit`` or attempted to deposit more RDN than the UDC limit would allow
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.


**Plan a withdraw**

.. http:post:: /api/(version)/user_deposit

   Before RDN can be withdrawn from the UDC the withdraw must be planned.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/v1/user_deposit HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "planned_withdraw_amount": "1500"
      }

   :reqjson string planned_withdraw_amount: The amount of tokens for which a withdrawal should get planned.

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
         "planned_withdraw_block_number": 4269933,
         "transaction_hash": "0xec6a0d010d740df20ca8b3b6456e9deaab8abf3787cb676ee244bef7d28aa4fc"
      }

   :statuscode 200: Withdraw plan was successful
   :statuscode 400: The provided JSON is in some way malformed
   :statuscode 402: Insufficient ETH to pay for the gas of the on-chain transaction
   :statuscode 404: No UDC is configured on the Raiden node
   :statuscode 409: The provided ``planned_withdraw_amount`` is higher than the balance in the UDC or not greater than zero
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.

**Withdraw**

.. http:post:: /api/(version)/user_deposit

   Withdraw RDN from the UDC. Can only be done 100 blocks after the withdraw was planned.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/v1/user_deposit HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "withdraw_amount": "1500"
      }

   :reqjson string withdraw_amount: The amount of tokens which should get withdrawn.

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
         "transaction_hash": "0xfc7edd195c6cc0c9391d84dd83b7aa9dbfffbcfc107e5c33a5ab912c0d92416c"
      }

   :statuscode 200: Withdraw was successful
   :statuscode 400: The provided JSON is in some way malformed
   :statuscode 402: Insufficient ETH to pay for the gas of the on-chain transaction
   :statuscode 404: No UDC is configured on the Raiden node
   :statuscode 409: The provided ``withdraw_amount`` is higher than the planned amount or not greater than zero or the withdraw is too early
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.


Connections
===========

The connections endpoints allow you to query details about all joined token networks as well as leave a token network by closing and settling all open channels.

**Details of All Joined Token Networks**

.. http:get:: /api/(version)/connections

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
               "sum_deposits": "67",
               "channels": "3"
         },
         "0x0f114A1E9Db192502E7856309cc899952b3db1ED": {
               "sum_deposits": "31",
               "channels": "1"
         }
      }

   :statuscode 200: For a successful query
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.
   :resjsonarr string sum_deposits: Sum of deposits in all currently open channels
   :resjsonarr string channels: Number of channels currently open for the specific token


.. _api_leave_tn:

**Leave a Token Network**

.. http:delete:: /api/(version)/connections/(token_address)

   The request might take some time because it will only return once all blockchain calls for closing and settling a channel have been completed.

   The response is a list with the addresses of all closed channels.

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

   :statuscode 200: Successfully leaving a token network
   :statuscode 404: The given token address is not a valid EIP55-encoded Ethereum address
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.

   .. note::
      Currently, the API calls are blocking. This means that in the case of long running calls like leave a token network, if an API call is currently being processed by Raiden, all pending calls will be queued and processed with their passed API call argument.
      

Pending Transfers
=================

The pending transfers endpoints let you query information about transfers that have not been completed yet.

.. http:get:: /api/(version)/pending_transfers

   Returns a list of all transfers that have not been completed yet.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/pending_transfers HTTP/1.1
      Host: localhost:5001

   See below for an example response.

.. http:get:: /api/(version)/pending_transfers/(token_address)

   Limits the response to pending transfers of the specified token.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/pending_transfers/0xd0A1E359811322d97991E03f863a0C30C2cF029C HTTP/1.1
      Host: localhost:5001

   See below for an example response.

.. http:get:: /api/(version)/pending_transfers/(token_address)/(partner_address)

   Limits the response to pending transfers of the specified token and channel.

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
            "token_network_address": "0x111157460c0F41EfD9107239B7864c062aA8B978",
            "transferred_amount": "331"
         }
      ]

   :statuscode 200: Successful query
   :statuscode 404: The queried channel or token was not found
   :statuscode 500: Internal Raiden node error
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.
   :resjsonarr string role: One of "initiator", "mediator" and "target"


Notifications
=============

.. http:get:: /api/(version)/notifications

   Raiden can inform the user about conditions that may require an action by the user or their attention.
   These are the types of notifications that currently can be returned, listed by ``id``:

   * ``low_rdn``: RDN tokens deposited in the UDC are below a threshold.
   * ``version_outdated``: Running an outdated version of Raiden.
   * ``missing_gas_reserve``: ETH balance is below a threshold and you may not be able to perform on-chain transactions.
   * ``version_security_warning``: There is an important security update.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      GET /api/v1/notifications HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      [
         {
            "body": "WARNING\nYour account's RDN balance deposited in the UserDepositContract of 0.0 is below the minimum threshold 5.5. Provided that you have either a monitoring service or a path finding service activated, your node is not going to be able to pay those services which may lead to denial of service or loss of funds.",
            "id": "low_rdn",
            "summary": "RDN balance too low",
            "urgency": "normal"
         },
         {
            "body": "You're running version 1.1.1.dev630+g43ae6e32b. The latest version is 1.2.0It's time to update! Releases: https://github.com/raiden-network/raiden/releases",
            "id": "version_outdated",
            "summary": "Your version is outdated",
            "urgency": "normal"
         }
      ]


Shutdown
========

.. http:post:: /api/(version)/shutdown

   You can call the shutdown endpoint to stop a running Rainde node.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/v1/shutdown HTTP/1.1
      Host: localhost:5001

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
         "status": "shutdown"
      }


Testing
=======

You can mint tokens for testing purposes by making a request to the ``_testing`` endpoint. 
This is only possible on testnets.

**Mint Tokens**

.. http:post:: /api/(version)/_testing/tokens/(token_address)/mint

   This requires the token at ``token_address`` to implement a minting method with one of
   the common interfaces:

   - ``mint(address,uint256)``

   - ``mintFor(uint256,address)``

   - ``increaseSupply(uint256,address)``

   Depending on the token, it may also be necessary to have minter privileges.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/v1/_testing/tokens/0x782CfA3c74332B52c6f6F1758913815128828209/mint HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
         "to": "0x2c4b0Bdac486d492E3cD701F4cA87e480AE4C685",
         "value": "1000"
      }

   :reqjson address to: The address to assign the minted tokens to.
   :reqjson string value: The amount of tokens to be minted.

   **Example Response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
         "transaction_hash": "0x90896386c5b218d772c05586bde5c37c9dc90db5de660bba5bd897705c976edb"
      }

   :statuscode 200: The transaction was successful.
   :statuscode 400: Something went wrong.
   :statuscode 503: The API is currently unavailable, e. g. because the Raiden node is still in the initial sync or shutting down.
   :resjson string transaction_hash: The hash of the minting transaction.
