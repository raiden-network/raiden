.. _api_tut_open_channel:

Open a Channel
==============

This section will cover the endpoints you would use to:

1. Find suitable partner nodes
2. :ref:`Open a channel <api_tut_open_channel>`
3. :ref:`Query the state of a channel <api_tut_channel_state>`

.. _find_partner:

Find suitable partner nodes
---------------------------

To make payments, you need to be connected to the target node either
directly, or indirectly by having a channel with a well connected that
mediates your payment to the target. If you already know to which node
you want to connect, skip ahead to the `next section <Open a channel>`.

The Path Finding Service (PFS) can suggest partners that are highly
connected. These nodes will be able to mediate your payments to a large
amount of potential targets and are thus a good choice for your first
channel(s). Ask the PFS by sending a GET request to its partner
suggestion endpoint for the token you want to use.

.. code:: bash

   curl https://pfs.of.your.choice/api/v1/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/suggest_partner

If you don't know which PFS to ask, you can get the URL of the PFS used
by your Raiden node from the :ref:`settings endpoint <api_settings>`. The
list of suggested partners is sorted with the most recommended ones
coming first. If you want to open just a single channel, picking the
address of the first partner in the results is a reasonable choice.

.. code:: javascript

   [
     {
       "address": "0x99eB1aADa98f3c523BE817f5c45Aa6a81B7c734B",
       "score": 2906634538666422000,
       "centrality": 0.0004132990448199853,
       "uptime": 7032.763746,
       "capacity": 1000000000000000000
     },
     {
       "address": "0x4Fc53fBa9dFb545B66a0524216c982536012186e",
       "score": 2906693668947465000,
       "centrality": 0.0004132990448199853,
       "uptime": 7032.906815,
       "capacity": 1000000000000000000
     }
   ]

.. _open-a-channel-1:

Open a channel
--------------

To open a channel a PUT request is made to the
:ref:`channels <api_open_channel>` endpoint
that includes a JSON object containing:

1. The address of the node you'd like to open the channel with.
2. The amount of tokens you want to deposit in the channel. (Remember
   that it is always possible to :ref:`deposit more tokens <api_increase_deposit>`
   later.)
3. The settle timeout period which corresponds to the number of blocks
   that have to be mined before a closed channel can be settled.

.. code:: bash

   curl -i -X PUT \
   http://localhost:5001/api/v1/channels \
   -H 'Content-Type: application/json' \
   --data-raw '{"partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9", "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700", "total_deposit": "1337", "settle_timeout": "500"}'

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

You're now ready to start making payments.

.. include:: 3-make-a-payment.inc.rst

.. note:: Opening a channel with a partner node is not dependent on whether the partner node holds tokens or not. It will work either way. 

.. _api_tut_channel_state:

Query the state of a channel
----------------------------

Checking the current state of a channel is as easy as making a query to
the :ref:`channels <api_channel_info>` endpoint while providing:

1. The token address as a path parameter.
2. The address of the partner node as a path parameter.

.. code:: bash

   curl -i \
   http://localhost:5001/api/v1/channels/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/0x61C808D82A3Ac53231750daDc13c777b59310bD9

This will give you the same response object as when :ref:`opening a channel <api_tut_open_channel>`.
