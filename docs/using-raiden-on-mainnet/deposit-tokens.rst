Deposit Tokens
==============

You deposit in a channel by making a PATCH request to the
:ref:`channels <api_increase_deposit>`
endpoint that includes:

1. The address of the W-ETH token as a path parameter.
2. The address of the partner node as a path parameter.
3. The amount of tokens you want to deposit in the channel as a body
   parameter.

.. code:: text

   curl -i -X PATCH \
   http://localhost:5001/api/v1/channels/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/<partner_address> \
   -H 'Content-Type: application/json' \
    --data-raw '{"total_deposit":"4000"}'

.. note::

   Notice how we are specifying the ``total_deposit`` in the request and not only the amount we want to "top-up" with. This means that if we initially deposited 2000 WEI and want to increase the amount with 2000 we would need to make a total deposit of 4000 WEI.

   This is done to prevent requests that are sent repeatedly (by accident or as part of an attack) from having any further consequences. 

