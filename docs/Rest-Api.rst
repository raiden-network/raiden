Raiden's API Documentation
##########################


Contents:

.. toctree::
   :maxdepth: 2



Introduction
*************
Raiden has a Restful API with URL endpoints corresponding to actions that the user can perform with his channels. The endpoints accept and return JSON encoded objects. The api url path always contains the api version in order to differentiate queries to
different API versions. All queries start with: ``/api/<version>/``



JSON Object Encoding
********************

The objects that are sent to and received from the API are JSON-encoded. Following are the common objects used in the API.

Channel Object
===============
::

    {
       "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
       "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
       "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
       "balance": 35000000,
       "state": "open",
       "settle_timeout": 100
    }



A channel object consists of a

- ``channel_address`` should be a ``string`` containing the hexadecimal address of the
  channel

- ``partner_address`` should be a ``string`` containing the hexadecimal address of the
  partner with whom we have opened a channel

- ``token_address`` should be a ``string`` containing the hexadecimal address of the
  token we are trading in the channel.

- ``balance`` should be an integer of the amount of the ``token_address`` token we have available for transferring.

- ``state`` should be the current state of the channel represented by a string.
  Possible value are:
  - ``'opened'``: The channel is open and tokens are tradeable
  - ``'closed'``: The channel has been closed by a participant
  - ``'settled'``: The channel has been closed by a participant and also settled.

- ``'settle_timeout'``: The number of blocks that are required to be mined from the time that ``close()`` is called
                        until the channel can be settled with a call to ``settle()``.


Event Object
==============

Channels events are encoded as json objects with the event arguments as attributes
of the dictionary, with one difference. The ``event_type`` is also added for all events to easily distinguish between events.






Endpoints
***********

Following are the available API endpoints with which you can interact with Raiden.

Querying Information About Your Raiden Node
===============================================

Querying your address
---------------------

When raiden starts you choose an ethereum address which will also be your raiden address. You can query that address by making a ``GET`` request to the ``/api/<version>/address`` endpoint.

Example Request
^^^^^^^^^^^^^^^

``GET /api/1/address``

Example Response
^^^^^^^^^^^^^^^^
``200 OK`` and

::

    {"our_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226"}

Deploying
=========

Registering a Token
-------------------

If a Token is not registered (i.e.: A channel manager for that token does not exist in the network) then we need to register it by deploying a Channel Manager contract for that token.

We can do that by doing a ``PUT`` request to the endpoint ``/api/<version>/tokens/<token_address>``. The request should return the deployed channel manager's address.

If the token is already registered then a 409 Conflict error is returned.

Example Request
^^^^^^^^^^^^^^^

``PUT /api/1/tokens/0xea674fdde714fd979de3edf0f56aa9716b898ec8``

Example Response
^^^^^^^^^^^^^^^^
+------------------+----------------------------+
| HTTP Code        | Condition                  |
+==================+============================+
| 201 Created      | For successful Registration|
+------------------+----------------------------+
| 409 Conflict     | If the token is already    |
|                  | registered                 |
+------------------+----------------------------+

And with a 201 response we also get::

    {"channel_manager_address": "0xC4F8393fb7971E8B299bC1b302F85BfFB3a1275a"}

Querying Information About Channels and Tokens
===============================================

Querying specific channel
--------------------------

There are multiple ways to query information about your channels. The most direct, if you know the channel address, is to query the channel master resource endpoint ``/api/<version>/channels/<channel_address>`` with a ``GET`` request.

Example Request
^^^^^^^^^^^^^^^

``GET /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226``

Example Response
^^^^^^^^^^^^^^^^
::

    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "balance": 35000000,
        "state": "open",
        "settle_timeout": 100
    }


The other ways to query information about the channels is to navigate the document
hierarchy of the API and find the channel address which will lead you to the master
resource as shown above.

Querying All Channels
--------------------------

By making a ``GET`` request to ``/api/<version>/channels`` you can get a list of all non-settled channels.


Example Request
^^^^^^^^^^^^^^^

``GET /api/1/channels``

Example Response
^^^^^^^^^^^^^^^^

``200 OK`` and

::

    [
        {
            "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
            "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
            "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
            "balance": 35000000,
            "state": "open",
            "settle_timeout": 100
        }
    ]

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For a successful Query    |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+



Querying all traded Tokens
--------------------------

By making a ``GET`` request to ``/api/<version>/tokens`` you get a list of addresses of all registered tokens.


Example Request
^^^^^^^^^^^^^^^

``GET /api/1/tokens``

Example Response
^^^^^^^^^^^^^^^^
``200 OK`` and

::

    [
        {"address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8"},
        {"address": "0x61bb630d3b2e8eda0fc1d50f9f958ec02e3969f6"}
    ]

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For a successful Query    |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+


Querying All Partners for a Token
-----------------------------------

By making a ``GET`` request to ``/api/<version>/tokens/<token_address>/partners`` you can get a list of all partners
you have non-settled channels with.

Example Request
^^^^^^^^^^^^^^^

``GET /api/1/tokens/0x61bb630d3b2e8eda0fc1d50f9f958ec02e3969f6/partners``

Example Response
^^^^^^^^^^^^^^^^
``200 OK``

::


    [
        {
            "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
            "channel": "/api/<version>/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226"
        }
    ]


Notice that you also get a link to the channel resource for the channel between you
and each partner for the token.

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For a successful Query    |
+------------------+---------------------------+
| 302 Redirect     | If the user accesses the  |
|                  | channel link endpoint     |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+

Token Swaps
------------

You can perform a token swap by using the ``token_swaps`` endpoint. A swap consists of two users agreeing on atomically exchanging two different tokens at a particular exchange rate.

By making a ``PUT`` request to ``/api/<version>/token_swaps/<target_address>/<identifier>`` you can either initiate or participate in a token swap with a specific user. The details, along with the role, come as part of the json payload.

Example Request
^^^^^^^^^^^^^^^

The maker (in our case ``0xbbc5ee8be95683983df67260b0ab033c237bde60``) would do

``PUT /api/1/token_swaps/0x61c808d82a3ac53231750dadc13c777b59310bd9/1337``

with payload
::

    {
        "role": "maker",
        "sending_amount": 42,
        "sending_token": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "receiving_amount": 76,
        "receiving_token": "0x2a65aca4d5fc5b5c859090a6c34d164135398226"
    }

and the taker (in our case ``0x61c808d82a3ac53231750dadc13c777b59310bd9``) would use:
``PUT /api/1/token_swaps/0xbbc5ee8be95683983df67260b0ab033c237bde60/1337``

::

    {
        "role": "taker",
        "sending_amount": 76,
        "sending_token": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "receiving_amount": 42,
        "receiving_token": "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    }

Please note that the sending/receiving amount and token is always from the perspective of each node. That is why you see the reverse values in the two different examples.

Example Response
^^^^^^^^^^^^^^^^
``201 CREATED``

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 201 Created      | For successful Creation   |
+------------------+---------------------------+
| 400 Bad Request  | If the provided json is in|
|                  | some way malformed        |
+------------------+---------------------------+
| 408 Request      | If the token swap         |
| Timeout          | operation times out       |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+

Channel Management
==================

Open Channel
------------

You can create a channel by posting a channel object to the following endpoint.

``PUT /api/<version>/channels``

Since it is a new channel, the channel object's ``channel_address`` and ``status``
field will be ignored and can be omitted.

Example Request
^^^^^^^^^^^^^^^

``PUT /api/1/channels`` with payload:::


    {
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "balance": 35000000,
        "settle_timeout": 100
    }



The ``balance`` field will signify the initial deposit you wish to make to the channel.

The request to the endpoint should later return the fully created channel object
from which we can find the address of the channel.

Example Response
^^^^^^^^^^^^^^^^
``201 Created`` and
::

    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "balance": 35000000,
        "state": "open",
        "settle_timeout": 100
    }

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 201 Created      | For successful Creation   |
+------------------+---------------------------+
| 400 Bad Request  | If the provided json is in|
|                  | some way malformed        |
+------------------+---------------------------+
| 408 Request      | If the deposit event was  |
|     Timeout      | not read in time by the   |
|                  | ethereum node             |
+------------------+---------------------------+
| 409 Conflict     | If the input is invalid,  |
|                  | such as too low settle    |
|                  | timeout                   |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+


Close Channel
--------------

You can close an existing channel by making a ``PATCH`` request to its endpoint and altering the state to closed.

``PATCH /api/<version>/channels/<channel_address>``

Example Request
^^^^^^^^^^^^^^^

``PATCH /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226``

with payload
``{"state":"closed"}``

Example Response
^^^^^^^^^^^^^^^^
``200 OK`` with
::

    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "balance": 35000000,
        "state": "closed",
        "settle_timeout": 100
    }

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For successful Closing    |
+------------------+---------------------------+
| 400 Bad Request  | If the provided json is in|
|                  | some way malformed        |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+


Settle Channel
---------------

You can settle an existing channel by making a ``PATCH`` request to its endpoint and altering the state to settled.

``PATCH /api/<version>/channels/<channel_address>``

Example Request
^^^^^^^^^^^^^^^

``PATCH /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226``

with payload
``{"state":"settled"}``

Example Response
^^^^^^^^^^^^^^^^
``200 OK`` with
::

    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "balance": 0,
        "state": "settled",
        "settle_timeout": 100
    }

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For successful Settlement |
+------------------+---------------------------+
| 400 Bad Request  | If the provided json is in|
|                  | some way malformed        |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+

Deposit to a Channel
---------------------

You can deposit more of a particular token to a channel by updating the ``balance``
field of the channel in the corresponding endpoint with a ``PATCH`` http request.

``PATCH /api/<version>/channels/<channel_address>``

Example Request
^^^^^^^^^^^^^^^

``PATCH /api/1/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226``

with payload

``{"balance": 100}``

Example Response
^^^^^^^^^^^^^^^^
``200 OK`` with
::

    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "balance": 100,
        "state": "open",
        "settle_timeout": 100
    }

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For successful Deposit    |
+------------------+---------------------------+
| 400 Bad Request  | If the provided json is in|
|                  | some way malformed        |
+------------------+---------------------------+
| 408 Request      | If the deposit event was  |
|     Timeout      | not read in time by the   |
|                  | ethereum node             |
+------------------+---------------------------+
| 402 Payment      | Insufficient balance to   |
|     required     | do a deposit              |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+

Connection Management
======================

Connecting to a token network
------------------------------

You can automatically join a token network by making a ``PUT`` request to the following endpoint along with a json payload
containing the connection details such as the funding you want to put into the network, the initial target for amount of channels to create and the target for joinable funds.

``PUT /api/<version>/connection/<token_address>``

The request will only return once the transfer either succeeded or failed. A transfer can fail due to the expiration of a lock.

Example Request
^^^^^^^^^^^^^^^

``PUT /api/v1/connection/0x2a65aca4d5fc5b5c859090a6c34d164135398226``

with payload::

    {
        "funds": 1337
    }


Example Response
^^^^^^^^^^^^^^^^
``204 NO CONTENT``

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 204 NO CONTENT   | For a successful          |
|                  | connection creation       |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+

Leaving a token network
-----------------------

You can leave a token network by making a ``DELETE`` request to the following endpoint along with a json payload containing
details about the way you want to leave the network. For instance if you want to wait for settlement and the timeout period.

``DELETE /api/<version>/connection/<token_address>``

The request will only return once the transfer either succeeded or failed. A transfer can fail due to the expiration of a lock.

Example Request
^^^^^^^^^^^^^^^

``DELETE /api/v1/connection/0x2a65aca4d5fc5b5c859090a6c34d164135398226``


Example Response
^^^^^^^^^^^^^^^^
``204 NO CONTENT``

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 204 NO CONTENT   | For successfully leaving  |
|                  | a token network           |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+

Transfers
=========

Initiating a Transfer
---------------------

You can create a new transfer by making a ``POST`` request to the following endpoint along with a json payload containing
the transfer details such as amount and identifier. Identifier is optional.

``POST /api/<version>/transfers/<token_address>/<target_address>``

The request will only return once the transfer either succeeded or failed. A transfer can fail due to the expiration of a lock.

Example Request
^^^^^^^^^^^^^^^

``POST /api/1/transfers/0x2a65aca4d5fc5b5c859090a6c34d164135398226/0x61c808d82a3ac53231750dadc13c777b59310bd9``

with payload::

  {
      "amount": 200,
      "identifier": 42
  }


Example Response
^^^^^^^^^^^^^^^^
200 OK with payload
::

    {
        "initiator_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
        "target_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "amount": 200,
        "identifier": 42
    }


Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For a successful Transfer |
|                  | creation                  |
+------------------+---------------------------+
| 400 Bad Request  | If the provided json is in|
|                  | some way malformed        |
+------------------+---------------------------+
| 408 Timeout      | If a timeout happened     |
|                  | during the transfer       |
+------------------+---------------------------+
| 402 Payment      | If the transfer can't     |
|     required     | start due to insufficient |
|                  | balance                   |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+


Querying Events
================

Events are kept by the node. Once an event endpoint is queried the relevant events
from either the beginning of time or the given block are returned.

Events are queried by two different endpoints depending on whether they are related
to a specific channel or not.

All events can be filtered down by providing the query string argument ``from_block``
to signify the block from which you would like the events to be returned.

Querying general network events
---------------------------------

.. NOTE::
   The network registry used is the default registry. The default registry is
   preconfigured and can be edited from the raiden configuration file.

You can query for registry network events by making a ``GET`` request to the
following endpoint. ``GET /api/<version>/events/network``

Example Request
^^^^^^^^^^^^^^^

``GET /api/1/events/network``

Example Response
^^^^^^^^^^^^^^^^
``200 OK`` with
::

    [
        {
            "event_type": "TokenAdded",
            "token_address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
            "channel_manager_address": "0xc0ea08a2d404d3172d2add29a45be56da40e2949"
        }, {
            "event_type": "TokenAdded",
            "token_address": "0x91337a300e0361bddb2e377dd4e88ccb7796663d",
            "channel_manager_address": "0xc0ea08a2d404d3172d2add29a45be56da40e2949"
        }
    ]

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For successful Query      |
+------------------+---------------------------+
| 400 Bad Request  | If the provided query     |
|                  | string is  malformed      |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+


Querying token network events
------------------------------

You can query for all new channels opened for a token by making a ``GET`` request to the following endpoint. ``GET /api/<version>/events/tokens/<token_address>``

Example Request
^^^^^^^^^^^^^^^

``GET /api/1/events/tokens/0x61c808d82a3ac53231750dadc13c777b59310bd9``

Example Response
^^^^^^^^^^^^^^^^
``200 OK`` with
::

    [
        {
            "event_type": "ChannelNew",
            "settle_timeout": 10,
            "netting_channel": "0xc0ea08a2d404d3172d2add29a45be56da40e2949",
            "participant1": "0x4894a542053248e0c504e3def2048c08f73e1ca6",
            "participant2": "0x356857Cd22CBEFccDa4e96AF13b408623473237A"
        }, {
            "event_type": "ChannelNew",
            "settle_timeout": 15,
            "netting_channel": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
            "participant1": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
            "participant2": "0xc7262f1447fcb2f75ab14b2a28deed6006eea95b"
        }
    ]

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For successful Query      |
+------------------+---------------------------+
| 400 Bad Request  | If the provided query     |
|                  | string is  malformed      |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+

Querying channel events
------------------------

You can query for events tied to a specific channel by making a ``GET`` request to the event endpoint of its address. ``GET /api/<version>/events/channels/<channel_registry_address>``

Example Request
^^^^^^^^^^^^^^^

``GET /api/1/events/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226?from_block=1337``

Example Response
^^^^^^^^^^^^^^^^
``200 OK`` with
::

    [
        {
            "event_type": "ChannelNewBalance",
            "participant": "0xea674fdde714fd979de3edf0f56aa9716b898ec8",
            "balance": 150000,
            "block_number": 54388
        }, {
            "event_type": "TransferUpdated",
            "token_address": "0x91337a300e0361bddb2e377dd4e88ccb7796663d",
            "channel_manager_address": "0xc0ea08a2d404d3172d2add29a45be56da40e2949"
        }, {
            "event_type": "EventTransferSentSuccess",
            "identifier": 14909067296492875713,
            "block_number": 26
        }
    ]

Possible Responses
^^^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| HTTP Code        | Condition                 |
+==================+===========================+
| 200 OK           | For successful Query      |
+------------------+---------------------------+
| 400 Bad Request  | If the provided query     |
|                  | string is  malformed      |
+------------------+---------------------------+
| 500 Server Error | Internal Raiden node error|
+------------------+---------------------------+
