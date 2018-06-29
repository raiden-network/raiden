Raiden Red Eyes Mainnet Tutorial
########################################

.. toctree::
  :maxdepth: 3

Introduction
=============
In this tutorial we show how to use Raiden to do off chain payments using the Raiden Network on the Ethereum mainnet. For this tutorial we use the Red Eyes (LINK TO RELEASE) release. More information on the Red Eyes release can be found here(INSERT LINK ONCE READY). Since the Red Eyes release is a bug bounty release(LINK TO BLOGPOST), certain limits have been made to the amount of tokens that can be deposited in channels. This is done in order to minimize the funds that are potentially lost in case something goes wrong.

Raiden has a Restful API with URL endpoints corresponding to actions that users can perform with their channels. The endpoints accept and return JSON encoded objects. The API URL path always contains the API version in order to differentiate queries to different API versions. All queries start with: ``/api/<version>/`` where ``<version>`` is an integer representing the current API version. (TODO: this part might be superfluous)

Before getting started with this tutorial, please see the :doc:`Installation Guide <overview_and_guide>`, to make sure that Raiden is correctly installed and running.

.. _join-token-network:

Joining a token network
==============================
The first thing we need to do is to join a token network. In this case we want to join the Raiden token (`RDN <https://etherscan.io/token/0x255aa6df07540cb5d3d297f0d0d4d84cb52bc8e6>`_) network.

*Note*: 1 RDN == 2**18 Rei. For the sake of readability and simplicity all token values in this tutorial are denominated in Rei and not RDN.

In order to do so, we need the address of the token and the initial amount of tokens that we want to join the network with::

    PUT /api/v2/connections/0x255aa6df07540cb5d3d297f0d0d4d84cb52bc8e6

TODO: check correctness of API
With the payload::

    {
        "funds": 20000
    }

This automatically connects our node to 3(TODO) other nodes in the network with 20000 / 5 Rei tokens in each channel.

We're now ready to start sending RDN tokens using the Raiden Network.

In case we know of a specific address in the network that we will do frequent transfers with, we can open a channel directly to this address by doing the following::

    PUT /api/v2/channels

With the payload::

    {
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "token_address": "0x255aa6df07540cb5d3d297f0d0d4d84cb52bc8e6",
        "balance": 2000,
        "settle_timeout": 60
    }
TODO: Update to have correct values

At this point the specific value of the ``balance`` field isn't too important, since it's always possible to :ref:`deposit more tokens <topping-up-a-channel>` to a channel if need be.

Successfully opening a channel returns the following information::

    {
        "channel_identifier": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "balance": 2000,
        "state": "opened",
        "settle_timeout": 60
    }

TODO: check correctness

.. _doing-payments:

Payments
========
Now that we have joined a token network, we can start making payments. For this, we need the address of the RDN token and the address of the recipient of the payment::

    POST /api/v2/transfers/0x255aa6df07540cb5d3d297f0d0d4d84cb52bc8e6/0x61c808d82a3ac53231750dadc13c777b59310bd9

In the payload we specify the amount of Rei of the payment::

    {
        "amount": 42
    }
TODO: Check for correctness.

In this specific case the payment goes directly to one of our channel partners, since we have an open channel with ``0x61c808d82a3ac53231750dadc13c777b59310bd9``. If we specify an address that we do not have a direct channel with, the Raiden Network finds a path to the target address and use mediated transfers to make a payment from our address to the target address.

It's as simple as that to do payments using the Raiden Network. The first payment is done after just two API calls - one to join the token network and one to do the transfer. The third call to open a direct channel is optional.

Let's say we know someone with the address ``0x00014853D700AE1F39BA9dbAbdeC1c8683CF1b2A``, who is also part of the RDN token network. Even though we do not have a channel with this person it is as easy as above to send a payment. All we need is the address::

    POST /api/v2/transfers/0x255aa6df07540cb5d3d297f0d0d4d84cb52bc8e6/0x00014853D700AE1F39BA9dbAbdeC1c8683CF1b2A

With the payload of the amount of Rei tokens we want to pay::

    {
        "amount": 73
    }
TODO: Check for correctness.

Just like this we can send payments to anyone who is part of the token network for the RDN token.

.. _topping-up-a-channel:

Depositing tokens
=================
If we are spending more tokens than we are receiving and hence depleting our channels, it it possible to "top up" channels. For this we need the channel identifier of the channel we want to top up::

    PATCH /api/v2/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226

with the payload::

    {
        "total_deposit": 4000
    }
TODO: Check for correctness

Notice that we need to specify the total deposit, not the amount we wish to top up: We initially deposited 2000 tokens and want to add 2000 more, so we give a ``total_deposit`` of 4000. This way the top-up request is idempotent - if it is sent repeatedly (by accident or as part of an attack) it will have no further effect.

.. _get-channel-status:

Channel status
==============
We can at any point in time see things like how many tokens we have spent in a specific channel and how many tokens we have received. We do this by querying the status of a specific channel by it ``channel_identifier``::

    GET /api/v2/channels/0x2a65aca4d5fc5b5c859090a6c34d164135398226

This returns the following JSON response::

    {
        "channel_identifier": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x61c808d82a3ac53231750dadc13c777b59310bd9",
        "balance": 3958,
        "state": "opened",
        "settle_timeout": 60
    }
TODO: Check correctness

We can see that the current balance of the channel is ``3958`` which matches with the two deposits and one payment we've made ``2000 + 2000 - 42``.

If we send more payments and receive some payments we can see how the ``balance`` of the channel updates accordingly.

Wrap-up
=============
It is easy to get started doing payments using the Raiden Network. As a matter of fact one can even receive tokens through the Raiden Network without having any ether or any tokens. To achieve this the receiver needs to have a full Raiden node running as well as rely on the senders of the payments to be willing to pay the transaction fees for the on-chain transactions.

This tutorial does not mention how to close and settle a specific channel or how to leave a token network. Please consult the :doc:`API documentation <rest_api>`.
