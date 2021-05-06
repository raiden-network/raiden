.. _webui_payment:

Make a Payment
==============

Payment channels allow for Raiden transfers to be made without the need to involve the actual blockchain.
If you have one or more channels open you can start making payments. If
you used :ref:`Quick Connect <webui_quick_connect>` three
channels were automatically opened with three nodes.

Let's walk through how to make a transfer.

Transfer
--------

After selecting a token network with open channels. Click on the
**"Transfer"** button, this will bring open the *transfer dialog*.

1. If you accessed the transfer dialog from the *all networks view*, you
   can select the token network you want to make payments in also here.
2. Enter the receiving address.
3. Enter the amount.
4. Click **"Send"** to complete the transfer.

.. note::

   **Minting tokens**

   When running Raiden on a testnet the WebUI lets you mint tokens to fund
   your account with additional tokens.

   To mint tokens, click the three dots on the top right of the token
   network view and choose **"Mint"**.

   Minting tokens is an on-chain transaction that will consume some of your
   ETH.

.. note::

   **How does payment channels work?**

   Payment channels enable parties to exchange tokens off-chain without
   involving the blockchain for every transaction.

   This helps to avoid the blockchain consensus bottleneck and makes
   transfers both faster and cheaper.

   Raiden lets users pay anyone in the network by using a path of connected
   payment channels to mediate payments. This means that *a user don't need
   to open channels with every node they want to send payments to*.

   A payment channel in Raiden is always backed by an on-chain deposit of
   tokens. Depositing tokens or opening payment channels are on-chain
   transactions which require transaction fees (gas) that are paid in ETH.
