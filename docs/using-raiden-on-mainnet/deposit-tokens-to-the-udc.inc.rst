.. _mainnet_tutorial_deposit_udc:

Deposit Tokens to the UDC
=========================

To do :ref:`mediated transfers <mainnet_tutorial_mediated_payments>` we need to have RDN (Raiden Network Tokens) in the UDC (User Deposit Contract) for paying the monitoring and pathfinding services.
This section will describe how to add Raiden Network Tokens to the UDC by making a call to the :ref:`User Deposit endpoint <api_user_deposit>` of the Raiden API.
The following POST request will deposit 100 RDN tokens to the UDC:

.. code:: bash

   curl -i -X POST \
   http://localhost:5001/api/v1/user_deposit \
   -H 'Content-Type: application/json' \
   --data-raw '{"total_deposit": "100000000000000000000"}'

.. note::
   Raiden utilizes a RESTful API where all URL paths starts with ``/api/`` followed by a version number. The current API version is ``1`` and therefore all requests begins with ``/api/v1/``.

The request will take a couple of minutes, because two on-chain transactions are performed: Approving the UDC to use RDN and Depositing RDN to the UDC.
When successfully completed the API will respond with a transaction hash.
