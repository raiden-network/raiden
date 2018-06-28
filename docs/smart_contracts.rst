Deployment and Usage of the Raiden Network Smart Contracts
==========================================================

Deploying
---------

.. highlight:: bash

To deploy the smart contracts use the provided utility script in
:code:`tools/deploy.py`. It expects an unencrypted hex-encoded private key as
its only argument. The account of the provided private key needs to hold enough
Ether to complete the deployment. At the time of writing a complete deployment
requires approximately 5.7 million gas.
Example::

    python deploy.py --pretty 1111111111111111111111111111111111111111111111111111111111111111

It will output a JSON formatted list of the deployed contracts / libraries
addresses. You should keep this for the next steps.


Using the Contracts
-------------------

It's possible to have Raiden use other contracts than the default ones
configured in `raiden/constants.py`. To do so use the following command line
options:

  - :code:`--discovery-contract-address` corresponds to `EndpointRegistry.sol`
  - :code:`--registry-contract-address` corresponds to `Registry.sol`


Verifying on Etherscan
----------------------

Due to the fact that the Raiden Network uses multiple contracts and libraries
verifying them on Etherscan_ is a bit more involved.

Generally it's important to use the `Contract Version 2.0 verifier`_. The
previous version 1 will not work and produce confusing error messages.

To verify the contract code on Etherscan_ follow these steps:

#. Enter the :code:`Registry`'s contract address in the Etherscan search field
#. Click "Contract Code"
#. Modify the URL to :code:`verifyContract2` to use the new verification tool
#. Enter the contract name (:code:`Registry`)
#. Select the used solc version
#. Choose whether the code was compiled using the optimizer. Currently the
   contracts deployed with the deploy script aren't optimized.
#. Paste the combined contract code into the provided text area
   The combined contract code can be generated with the
   :code:`tools/join-contracts.py` utility script::

    cd raiden/smart_contracts
    python ../../tools/join-contracts.py Registry.sol registry-joined.sol

#. Enter :code:`ChannelManagerLibrary` and its corresponding address into the
   Library_1 name and address text fields.
#. Click "Verify And Publish"
#. The Registry code should now be verified.

Perform the same steps for the :code:`EndpointRegistry`, :code:`NettingChannelLibrary`,
and :code:`ChannelManagerLibrary` contracts except that you don't need to enter
any library addresses.

The :code:`ChannelManagerContract` and `NettingChannelContract` contracts only
get deployed once a token has been added and a channel has been opened.

The easiest way to do so is to start raiden using the new contracts (see.
`Using the contracts`_ above) and then follow these steps:

#. Register a token. For example the RTT token::

    curl -X PUT http://localhost:5001/api/1/tokens/0x0f114A1E9Db192502E7856309cc899952b3db1ED

The call will return the channel manager address. You can use this to verify
the contract. To do so follow the same steps as before except this time use:

.. highlight:: python

#. :code:`ChannelManagerContract` as the contract name
#. Use the joined code from :code:`ChannelManagerContract.sol`
#. You need to provide the constructor arguments that were used to deploy the
   contract
#. In this case this is just the token address. To get the right format you can
   use pyethereum's :code:`encode_abi` function. For example::

    >>> from ethereum.abi import encode_abi
    >>> encode_abi(['address'], ['0f114a1e9db192502e7856309cc899952b3db1ed']).hex()
    '0000000000000000000000000f114a1e9db192502e7856309cc899952b3db1ed'

#. Place the output from the above call into the "Constructor Arguments" field
#. Enter :code:`ChannelManagerLibrary` and its corresponding address into the
   Library_1 name and address text fields.
#. The ChannelManagerContract is now verified

.. highlight:: bash

Similarly the :code:`NettingChannelContract` also is only deployed once a
channel has been opened. Again this can be accomplished by using the following
command::

    curl -X PUT -H "Content-Type: application/json" \
        http://localhost:5001/api/1/channels \
        -d '{"partner_address": "0x2222222222222222222222222222222222222222", "token_address": "0x0f114A1E9Db192502E7856309cc899952b3db1ED", "balance": 1}'

The call will return the information of the newly created channel. The important
one for our purposes is the :code:`channel_address`. This is the address of a
deployed :code:`NettingChannelContract`. To verify it follow the same steps as
before except:

.. highlight:: python

#. Use :code:`NettingChannelContract` as the name
#. Use the joined code from :code:`NettingChannelContract.sol`
#. Encode the constructor arguments as before. The arguments are:
   :code:`token_address`, :code:`own_address`, :code:`partner_address`,
   :code:`settle_timeout`::

    >>> from ethereum.abi import encode_abi
    >>> encode_abi(
    ...     ['address', 'address', 'address', 'uint256'],
    ...     ['0f114a1e9db192502e7856309cc899952b3db1ed', '001ee1b9b78de26879ac9db3854ce1430b339bee', '2222222222222222222222222222222222222222', 90]
    ... ).hex()
    0000000000000000000000000f114a1e9db192502e7856309cc899952b3db1ed000000000000000000000000001ee1b9b78de26879ac9db3854ce1430b339bee0000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000005a

#. Place the output from the above call into the "Constructor Arguments" field
#. Enter :code:`NettingChannelLibrary` and its corresponding address into the
   Library_1 name and address text fields.
#. The NettingChannelContract should now be verified

.. _Etherscan: https://ropsten.etherscan.io
.. _Contract Version 2.0 verifier: https://ropsten.etherscan.io/verifyContract2
