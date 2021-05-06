.. _webui_join_tn:

Join a Token Network
====================

To make payments in Raiden you first need to join the network by opening channels for the token you want to make payments with.
You can join a token network by either:

-  :ref:`Quick Connect <webui_quick_connect>`
-  :ref:`Registering a new token <webui_register_token>`

.. note::

   **What is a token?**

   Each token complies to its own ERC20 smart contract which has a total
   supply of tokens.

   These token contracts are like a registry where different amounts of the
   total supply is mapped to different owners.

.. note::

   **What is a token network?**

   Anyone running a Raiden node and owns a token can join a network with
   other nodes who own the very same token.

   All nodes registered within such network form a token network.

.. _webui_quick_connect:

Quick Connect
-------------

*Quick Connect* lets you automatically open channels to nodes
recommended by a Path Finding Service.

If you click the **"Transfer"** button without having any open channels
for the selected token you will get prompted to use *Quick Connect*.
Alternatively you can click the three dots on the top right of a token
network view and choose **"Quick Connect".**

When using *Quick Connect*:

-  Enter the total number of tokens you want to allocate
-  Distribute the token amount between the recommended partner nodes.
   Only if a deposit is selected for a node, a channel will be opened.

The amount you choose when connecting is what will be available for
making payments. You can always add more funds by depositing to a
channel.

.. warning:: *Quick Connect* is an on-chain activity that will consume some of your ETH. Opening fewer channels will reduce the gas cost proportionally.

You are now ready to :ref:`make your first payment <webui_payment>`!

.. _webui_register_token:

Registering a new token
-----------------------

.. warning:: Registering a new token is only relevant on the testnets. The tokens allowed on mainnet for the Alderaan release are DAI and W-ETH.


If you want to join the network for a token and that token is not
displayed in the list of tokens it might mean that it has not been
registered.

To register a token yourself:

1. Click **"Select network"** in the tokens view.
2. Click **"Add new network"**.
3. Enter the address of the token you'd like to register and click
   **"Register"**.

You can follow the steps for :ref:`Quick
Connect <webui_quick_connect>` to join the network
of your newly registered token.
