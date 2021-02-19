.. _withdraw-tokens:

Withdraw Tokens
===============

Similar to depositing, a PATCH call to the
:ref:`channel <api_withdraw>` endpoint is used
for withdrawing with the difference that a value for ``total_withdraw``
is provided in the request body.

So, whenever you'd like to make a withdraw your request needs to
include:

1. The token address as a path parameter.
2. The address of the node you have the channel with as a path
   parameter.
3. The amount of tokens you want to withdraw as a body parameter.

.. code:: bash

   curl -i -X PATCH \
   http://localhost:5001/api/v1/channels/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/0x61C808D82A3Ac53231750daDc13c777b59310bD9 \
   -H 'Content-Type: application/json' \
   --data-raw '{"total_withdraw": "200"}'

In the next section we will take a look at how to withdraw all tokens
for a channel and how to leave a token network completely.
