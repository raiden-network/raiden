Token Swaps using Raiden
########################

Introduction
=============

An atomic swap is a way to exchange one token with another in a decentralized fashion.
Raiden supports implementing 3rd-party token swaps functionality on top of the payments endpoint in :doc:`rest_api`.
This document will show a walk through of how to build an atomic swap application on top of Raiden using the payment API and the ``--resolver-endpoint`` CLI flag.

Here's how it could be done:

First step would be that a payment is initiated with only the secret hash (Secret is unknown to Raiden) through your preferred HTTP client library.

   **Example Request**:

   .. http:example:: curl wget httpie python-requests

      POST /api/v1/payments/0x2a65Aca4D5fC5B5C859090a6c34d164135398226/0x61C808D82A3Ac53231750daDc13c777b59310bD9 HTTP/1.1
      Host: localhost:5001
      Content-Type: application/json

      {
          "amount": 200,
          "identifier": 42,
          "secret_hash": "0x1f67db95d7bf4c8269f69d55831e627005a23bfc199744b7ab9abcb1c12353bd"
      }

This request will trigger Raiden to initiate a payment (Locked Transfer) to our channel partner just like a regular payment.
With the exception that Raiden does **not** know the secret that will be used to unlock the locked transfer.
As soon as the partner requests the secret, Raiden needs to fetch the secret from the application that initiated the
atomic swap. This is where the ``--resolver-endpoint`` comes to play.

For Raiden to be able to fetch the secret, an endpoint has to be exposed to Raiden so that Raiden can request the
secret through that endpoint. This is why your application should initially implement such an endpoint which
is requested using certain parameters and is expected to return the secret value.

For this to work, Raiden has to be started in the following manner:

``raiden --resolver-endpoint http(s)://host[:port]/endpoint``

What you call the endpoint and which host you choose is up to you. However, the endpoint should:
1. Be implemented on top of the HTTP(s) protocol.
2. Be able to accept a JSON Payload.
3. Response should be in JSON format.
4. Should return ``200 OK`` header in the case of a successful request, otherwise an error header such as ``400 Bad Request``.

The request payload looks as follows:

   .. code-block:: json

      {
          "token": "0x2a65Aca4D5fC5B5C859090a6c34d164135398226",
          "secrethash": "0x1f67db95d7bf4c8269f69d55831e627005a23bfc199744b7ab9abcb1c12353bd",
          "amount": 5,
          "payment_identifier": 101,
          "payment_sender": "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
          "expiration": 5302,
          "payment_recipient": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
          "reveal_timeout": 50,
          "settle_timeout": 500,
      }

Response should be a JSON object containing the ``secret`` value.

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
          "secret": "0x4c7b2eae8bbed5bde529fda2dcb092fddee3cc89c89c8d4c747ec4e570b05f66"
      }

This will trigger Raiden to send this secret to the target node. The target node can use this secret to unlock the transfer.
