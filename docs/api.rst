Raiden's API Documentation
=========================================


Contents:

.. toctree::
   :maxdepth: 2



Introduction
=============
Raiden has a Restful API with URL endpoints corresponding to actions that the user can perform with his channels. The endpoints accept and return JSON encoded objects.



JSON Object Encoding
====================

The ojects that are sent to and received from the API are JSON-encoded. Following are the common objects used in the API.

Channel Object
---------------

```
{
    'channel_address': '0x2a65aca4d5fc5b5c859090a6c34d164135398226'
    'partner_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    'asset_address': '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    'balance': 35000000
    'state': 'open'
}

```

A channel object consists of a

- `channel_address` should be a `string` containing the hexadecimal address of the
  channel

- `partner_address` should be a `string` containing the hexadecimal address of the
  partner with whom we have opened a channel

- `asset_address` should be a `string` containing the hexadecimal address of the
  asset we are trading in the channel.

- `balance` should be an integer of the amount of the `asset_address` token we have
  deposited in the channel

- `state` should be the current state of the channel represented by a string.
  Possible value are:
  - `'open'`: The channel is open and assets are tradeable
  - `'closed'`: The channel has been closed by a participant
  - `'settled'`: The channel has been closed by a participant and also settled.


Endpoints
=============

Following are the available API endpoints with which you can interact with Raiden.

Channel Management
-------------------

Open Channel
************

You can create a channel by posting a channel object to the following endpoint.

`PUSH /api/channels`

Since it is a new channel, the channel object's `channel_address` and `status`
field will be ignored and can be omitted. For example:

```
{
    'partner_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    'asset_address': '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    'balance': 35000000
}

```

The `balance` field will signify the initial deposit you wish to make to the channel.

The request to the endpoint should later return the fully created channel object
from which we can find the address of the channel.

```
{
    'channel_address': '0x2a65aca4d5fc5b5c859090a6c34d164135398226'
    'partner_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    'asset_address': '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    'balance': 35000000
    'state': 'open'
}
```

