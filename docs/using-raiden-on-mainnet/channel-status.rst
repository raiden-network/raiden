View Channel Status
===================

To view the status of a channel you have to make a GET request to the
:ref:`channels endpoint <api_open_channel>` and provide:

1. The address of the W-ETH token as a path parameter.
2. The address of the partner node as a path parameter.

.. code:: text

   curl -i \
   http://localhost:5001/api/v1/channels/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C

This will return the following response object:

.. code:: text

   HTTP/1.1 201 CREATED
   Content-Type: application/json

   {
       "token_network_address": "0xE5637F0103794C7e05469A9964E4563089a5E6f2",
       "channel_identifier": "0xa24f51685de3effe829f7c2e94b9db8e9e1b17b137da5",
       "partner_address": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
       "token_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
       "balance": "3958",
       "state": "open",
       "settle_timeout": "500",
       "reveal_timeout": "50"
   }

As you can tell by the response, the current balance in the channel is
``3958`` which matches the two deposits and one payment you've just made
(``2000`` + ``2000`` - ``42`` = ``3958`` ).
