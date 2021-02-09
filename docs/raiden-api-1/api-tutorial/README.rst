API Tutorial
############

We will outline the steps necessary for participating in a token
network. To see all available endpoints visit the
:ref:`resources <api_endpoints>` part of the documentation.

In the examples throughout this tutorial we will be using a hypothetical
ERC20 token with the address ``0x9aBa529db3FF2D8409A1da4C9eB148879b046700``.

Check if Raiden was started correctly
=====================================

Before we start we'll make sure that Raiden is running correctly.

This gives us an opportunity to introduce the
:ref:`address <api_address>` endpoint.

.. code:: bash

   curl -i http://localhost:5001/api/v1/address

Your Raiden node is up and running if the response returns the same
address as the Ethereum address used for starting Raiden.

Overview
========

You're now ready to start interacting with the different endpoints and
learn how they can be used to:

.. include:: 1-join-a-token-network.rst

.. include:: 2-open-a-channel.rst

.. include:: 3-deposit.rst

.. include:: 3-make-a-payment.rst

.. include:: withdraw-tokens.rst

.. include:: 4-settle-payments-and-close-channels.rst
