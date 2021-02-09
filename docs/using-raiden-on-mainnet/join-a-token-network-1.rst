Open a Channel
==============

To open a channel, a PUT request is made to the
:ref:`channels endpoint <api_open_channel>` that includes a JSON object containing:

1. The address of the node you'd like to open the channel with. If you
   don't know to which partner you should connect, have a look at :ref:`find_partner`.
2. The token address. We use W-ETH token in this example.
3. The amount of tokens you want to deposit in the channel (Remember
   that it is always possible to :ref:`deposit more
   tokens <api_increase_deposit>` later). 1 W-ETH
   is equivalent to 10^18 WEI.
4. The settle timeout period which corresponds to the number of blocks
   that have to be mined before a closed channel can be settled.

.. code:: bash

   curl -i -X PUT \
   http://localhost:5001/api/v1/channels \
   -H 'Content-Type: application/json' \
   --data-raw '{"partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9", "token_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "total_deposit": "1337", "settle_timeout": "500"}'

.. note::

    Raiden utilizes a RESTful API where all URL paths starts with ``/api/`` followed by a version number. The current API version is ``1`` and therefore all requests begins with ``/api/v1/``. 


This will create a new channel and a successful request will return you
the following response object:

.. code:: bash

   HTTP/1.1 201 CREATED
   Content-Type: application/json

   {
       "token_network_address": "0x3C158a20b47d9613DDb9409099Be186fC272421a",
       "channel_identifier": "99",
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
       "balance": "1337",
       "total_deposit": "1337",
       "total_withdraw": "0",
       "state": "opened",
       "settle_timeout": "500",
       "reveal_timeout": "50"
   }

As you can tell by the response object a channel identifier has been
generated. This means that there now is a channel with that identifier
inside the token network.

We're now ready to start sending W-ETH tokens!

.. include:: make-a-payment.rst
