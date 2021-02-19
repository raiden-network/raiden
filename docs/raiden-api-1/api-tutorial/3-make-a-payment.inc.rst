.. _api_tut_make_payment:

Make a Payment
==============

A powerful feature of Raiden is the ability to let you **pay anyone in
the network** by using a path of connected payment channels to mediate
the payment and not only directly connected nodes. These payments are
called **mediated transfers**.

Pay
---

Payments are made from the
:ref:`payments <api_init_payment>` endpoint
via a POST request that needs to include:

1. The address of the token you want to pay with as a path parameter.
2. The address of the node receiving your payment as a path parameter.
3. The amount you would like to pay as a body parameter.

.. code:: bash

   curl -i -X POST \
   http://localhost:5001/api/v1/payments/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/0x61C808D82A3Ac53231750daDc13c777b59310bD9 \
   -H 'Content-Type: application/json' \
   --data-raw '{"amount": "42"}'

.. note::

   You can provide the body parameter with an additional *identifier* key with a value of your choice. This value can be a number (``"identifier": 42``) or the stringified number (``"identifier": "42"``).

   This is optional and the purpose of the identifier is to give dApps built on Raiden a way to tag payments. 

Your payment will most likely succeed if:

-  The path of channels leading from your node to the node receiving
   your payment has enough capacity.
-  All nodes needed to mediate the payment are online.
-  You have enough tokens in the channel from which you intend to pay
   out the amount specified in the request body.

To get your tokens out of a channel and back on-chain you either have to
:ref:`withdraw the tokens <withdraw-tokens>` or :ref:`close the channel <settle-and-close>`.


View payment history
--------------------

You can view all transactions you've made with a partner node by
querying the :ref:`payments <api_list_payments>`
endpoint in a GET request, using the same path parameters as when
:ref:`making a payment <api_tut_make_payment>`.

.. code:: bash

   curl -i \
   http://localhost:5001/api/v1/payments/0x9aBa529db3FF2D8409A1da4C9eB148879b046700/0x61C808D82A3Ac53231750daDc13c777b59310bD9

In the response you will be able to see all successful payments, all
failed payments and all payments you have received.
