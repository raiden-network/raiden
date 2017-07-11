Raiden Testnet deployment tools
===============================

This directory contains tools to deploy a complete raiden test network
running on Ropsten_ to AWS.

.. _Ropsten: https://github.com/ethereum/ropsten

Requirements
------------

* terraform_
* terraform-inventory_
* awscli_
* ansible_
* docker_

#. Ensure both terraform_ and terraform-inventory_ are installed into the PATH.
   On macOS both are available via homebrew.

#. Install awscli_ and ansible_ outside the raiden virtualenv to prevent
   dependency conflicts. It's recommended to avoid global installation and
   rather use a tool for isolated installation, for example pipsi_.

#. Make sure your aws credentials are saved and a 'us-east-1' has been
   selected as the default region (use `aws configure`).

#. Place the private SSH key 'id_raiden_testnet` into the `keys` directory

.. _terraform: https://www.terraform.io/downloads.html
.. _terraform-inventory: https://github.com/adammck/terraform-inventory/releases/tag/v0.7-pre
.. _awscli: https://pypi.org/project/awscli/
.. _ansible: https://pypi.org/project/ansible/
.. _docker: https://docker.io
.. _pipsi: https://github.com/mitsuhiko/pipsi/


Usage
-----

Configuration
*************

The deployment is configured via variables in 'variables.tf' and
'group_vars/all.yml'.


Initialize / Update
*******************

To initialise or update the testnet simply run::

    make

If no changes have been made to the dockerfiles you can also use::

    make up


To get a preview of what aws resources would be changed after changing the
terrafrom configuration you can use::

    terraform plan


Destroy
*******

To destroy the testnet and free all aws resources run::

    make down


List
****

To get a list of IP addresses of running instances run::

    terraform output


To gather the ethereum accounts used by the raiden nodes use::

    ansible-playbook playbook-get_eth_addresses.yml

This will place a list of the addresses in '$TMP/testnet_eth_addresses'.
That file can be used with the 'transfer_eth.py' script in the parent directory
to supply those addresses with ether.



TODO: Add instructions on how to interacting with / use the testnet
