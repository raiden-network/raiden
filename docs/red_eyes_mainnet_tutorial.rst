Raiden Red Eyes Mainnet Tutorial
########################################

.. toctree::
  :maxdepth: 3

Introduction
=============
In this tutorial we show how to use Raiden to do off chain payments using the Raiden Network on the Ethereum mainnet. For this tutorial we use the `Red Eyes release <https://github.com/raiden-network/raiden/releases/tag/v0.100.1>`_. More information on the Red Eyes release can be found `here <https://medium.com/raiden-network/red-eyes-mainnet-release-announcement-d48235bbef3c>`_. Since the Red Eyes release is a `bug bounty release <https://bounty.raiden.network>`_, certain limits have been made to the amount of tokens that can be deposited in channels. This is done in order to minimize the funds that are potentially lost in case something goes wrong.

Raiden has a Restful API with URL endpoints corresponding to actions that users can perform with their channels. The endpoints accept and return JSON encoded objects. The API URL path always contains the API version in order to differentiate queries to different API versions. All queries start with: ``/api/<version>/`` where ``<version>`` is an integer representing the current API version. The current version is version 1.

Before getting started with this tutorial, please see the :doc:`Installation Guide <overview_and_guide>`, to make sure that Raiden is correctly installed and running.

.. _about-weth:

About W-ETH
===========

For the Red Eyes Mainnet release only W-ETH can be used with the Raiden Network. W-ETH stands for wrapped Ether, meaning that Ether is packaged to conform to
the ERC20 token guidelines which Raiden relies on. To learn more about W-ETH you can read the `announcement blog post <https://blog.0xproject.com/canonical-weth-a9aa7d0279dd>`_.

To create W-ETH from your Ether you can either use interfaces like `0x OTC <https://0xproject.com/otc>`_ or `Radar Relay <https://radarrelay.com/>`_. You can also use the `contract <https://etherscan.io/address/0x2956356cd2a2bf3202f771f50d3d14a367b48070#code>`_ directly.


.. _join-token-network:

Joining a token network
==============================
The first thing we need to do is to join a token network. In this case we want to join the (`W-ETH <https://etherscan.io/address/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2>`_) network.

*Note*: 1 W-ETH == 10**18 wei. For the sake of readability and simplicity all token values in this tutorial are denominated in wei and not W-ETH.

In order to do so, we need the address of the token and the initial amount of tokens that we want to join the network with:

.. http:example:: curl wget httpie python-requests

    PUT /api/v1/connections/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 HTTP/1.1
    Host: localhost:5001
    Content-Type: application/json

    {
        "funds": 20000
    }

This automatically connects our node to 3 other nodes in the network with 20000 / 5 wei tokens in each channel.

We're now ready to start sending W-ETH tokens using the Raiden Network.

In case we know of a specific address in the network that we will do frequent payments to, we can open a channel directly to this address by doing the following:

.. http:example:: curl wget httpie python-requests

   PUT /api/v1/channels HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

   {
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
       "balance": 2000,
       "settle_timeout": 600
   }

At this point the specific value of the ``balance`` field isn't too important, since it's always possible to :ref:`deposit more tokens <topping-up-a-channel>` to a channel if need be.

Successfully opening a channel returns the following information:

.. sourcecode:: http

   HTTP/1.1 201 CREATED
   Content-Type: application/json

   {
       "channel_identifier": 13,
       "token_network_identifier": "0x3C158a20b47d9613DDb9409099Be186fC272421a",
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
       "balance": 2000,
       "total_deposit": 2000,
       "state": "opened",
       "settle_timeout": 600,
       "reveal_timeout": 10
   }

.. _doing-payments:

Payments
========
Now that we have joined a token network, we can start making payments. For this, we need the address of the W-ETH token and the address of the recipient of the payment:

.. http:example:: curl wget httpie python-requests

    POST /api/v1/payments/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
    Host: localhost:5001
    Content-Type: application/json

    {
        "amount": 42
    }

In this specific case the payment goes directly to one of our channel partners, since we have an open channel with ``0x61C808D82A3Ac53231750daDc13c777b59310bD9``. If we specify an address that we do not have a direct channel with, the Raiden Network finds a path to the target address and use mediated transfers to make a payment from our address to the target address.

It's as simple as that to do payments using the Raiden Network. The first payment is done after just two API calls - one to join the token network and one to do the payment. The third call to open a direct channel is optional.

Let's say we know someone with the address ``0x00014853D700AE1F39BA9dbAbdeC1c8683CF1b2A``, who is also part of the W-ETH token network. Even though we do not have a channel with this person it is as easy as above to send a payment. All we need is the address:

.. http:example:: curl wget httpie python-requests

    POST /api/v1/payments/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/0x00014853D700AE1F39BA9dbAbdeC1c8683CF1b2A HTTP/1.1
    Host: localhost:5001
    Content-Type: application/json

    {
        "amount": 73
    }

Just like this we can send payments to anyone who is part of the token network for the W-ETH token.

.. _topping-up-a-channel:

Depositing tokens
=================
If we spend more tokens than we receive and hence deplete our channels, it it possible to "top up" channels. For this we need the token address and the partner address:

.. http:example:: curl wget httpie python-requests

   PATCH /api/v1/channels/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json

   {
        "total_deposit": 4000
   }

Notice that we need to specify the total deposit, not the amount we wish to top up: We initially deposited 2000 tokens and want to add 2000 more, so we give a ``total_deposit`` of 4000. This way the top-up request is idempotent - if it is sent repeatedly (by accident or as part of an attack) it will have no further effect.

.. _get-channel-status:

Channel status
==============
We can at any point in time see things like how many tokens we have spent in a specific channel and how many tokens we have received. We do this by querying the status of a specific channel by it's ``channel_identifier``:

.. http:example:: curl wget httpie python-requests

    GET /api/v1/channels/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
    Host: localhost:5001
    Content-Type: application/json

This returns the following JSON response::

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "token_network_identifier": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
          "channel_identifier": "0xa24f51685de3effe829f7c2e94b9db8e9e1b17b137da59fa727a793ae2cae776",
          "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "token_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
          "balance": 3958,
          "state": "open",
          "settle_timeout": 600,
          "reveal_timeout": 30
      }

We can see that the current balance of the channel is ``3958`` which matches with the two deposits and one payment we've made ``2000 + 2000 - 42``.

If we send more payments and receive some payments we can see how the ``balance`` of the channel updates accordingly.

Wrap-up
=============
It is easy to get started doing payments using the Raiden Network. As a matter of fact one can even receive tokens through the Raiden Network without having any ether or any tokens. To achieve this the receiver needs to have a full Raiden node running as well as rely on the senders of the payments to be willing to pay the transaction fees for the on-chain transactions.

This tutorial does not mention how to close and settle a specific channel or how to leave a token network. Please consult the :doc:`API documentation <rest_api>`.
