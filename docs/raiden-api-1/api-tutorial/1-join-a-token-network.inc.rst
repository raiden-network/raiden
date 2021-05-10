Create a Token Network
======================

Check if the token is registered
--------------------------------

Before you can join a token network you need to determine whether the
token has been registered and a network for the token has been created.

We can verify this by making a query to the :ref:`tokens <api_tokens>` endpoint.

.. code:: bash

   curl -i http://localhost:5001/api/v1/tokens

If the address exists in the list returned by the response you can go
ahead and :ref:`open a channel <api_tut_open_channel>` in
that token network.

If the address is not in the list you'll have to register the token before you can open a channel.

.. _api_tut_register_token:

Register a new token
--------------------

Registering a new token is as simple as calling the
:ref:`tokens <api_tokens>` endpoint with a
PUT request while providing the address of the token you want to
register as a path parameter.

.. code:: bash

   curl -i -X PUT http://localhost:5001/api/v1/tokens/0x9aBa529db3FF2D8409A1da4C9eB148879b046700 \
   -H 'Content-Type: application/json'

If the call is successful the response will return a new address of the
now newly created token network.

.. code:: bash

   HTTP:/1.1 201 CREATED
   Content-Type: application/json

   {
       "token_network_address": "0xC4F8393fb7971E8B299bC1b302F85BfFB3a1275a"
   }

Because this token was just registered by you, no one else will be
connected to its network and you'll have to open a channel with another
Raiden node.

.. note::
   
   Payment channels between parties are opened in token networks.

.. warning::

   Registering a new token is currently only relevant on the testnets. The
   tokens allowed on the mainnet for the Alderaan release are DAI and W-ETH. At
   some point in future, you will be able to register new token networks for
   the Ethereum mainnet, too. 
