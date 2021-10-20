.. _settle-and-close:

Settle Payments and Close Channels
==================================

You can choose to either:

1. Close a specific channel
2. Leave a token network and close all channels

Close a specific channel
------------------------

Closing a specific channel is done with a PATCH request to the
:ref:`channels <api_close_channel>` endpoint that includes:

1. The token address as a path parameter.
2. The address of the partner node as a path parameter.
3. The state set to *"closed"* in the body parameter.

.. code:: bash

   curl -i -X PATCH \
   http://localhost:5001/api/v1/channels/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/0x61C808D82A3Ac53231750daDc13c777b59310bD9 \
   -H 'Content-Type: application/json' \
   --data-raw '{"state": "closed"}'

A successful response will return a normal channel object with the state
set to ``"closed"``.

.. code:: bash

   HTTP/1.1 200 OK
   Content-Type: application/json

   {
       "token_network_address": "0x3C158a20b47d9613DDb9409099Be186fC272421a",
       "channel_identifier": "99",
       "network_state": "unknown",
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
       "balance": "350",
       "total_deposit": "7331",
       "total_withdraw": "0",
       "state": "closed",
       "settle_timeout": "500",
       "reveal_timeout": "50"
   }

.. note:: The settle timeout period will start as soon as a channel is closed and the channel is settled once the settle timeout period is over. The state of the channel will then be changed to ``settled``.

Leave a token network and close all channels
--------------------------------------------

If you wish to leave a token network altogether you can do so by making
a DELETE request to the :ref:`connections <api_leave_tn>`
endpoint with the token address as a path parameter.

.. code:: bash

   curl -i -X DELETE \
   http://localhost:5001/api/v1/connections/0x9aBa529db3FF2D8409A1da4C9eB148879b046700 \
   -H 'Content-Type: application/json'

Once done, the response will return a list of channel-state objects of all closed channels.

.. code:: bash

   HTTP/1.1 200 OK
   Content-Type: application/json

   [
        {
            "token_network_address": "0x3C158a20b47d9613DDb9409099Be186fC272421a",
            "channel_identifier": "99",
            "network_state": "unknown",
            "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
            "token_address": "0x9aBa529db3FF2D8409A1da4C9eB148879b046700",
            "balance": "350",
            "total_deposit": "7331",
            "total_withdraw": "0",
            "state": "closed",
            "settle_timeout": "500",
            "reveal_timeout": "50"
        }
   ]

.. note::

   Please note that leaving a token network will take some time since you need
   to wait for the settle timeout to expire for each channel before a settle
   can happen.
