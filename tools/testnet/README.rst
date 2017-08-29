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
* ansible_ >= 2.3
* docker_

#. Ensure both terraform_ and terraform-inventory_ are installed into the PATH.
   On macOS both are available via homebrew.

#. Install awscli_ and ansible_ *outside* the raiden virtualenv to prevent
   dependency conflicts. It's recommended to avoid global installation and
   rather use a tool for isolated installation, for example pipsi_.

#. Make sure your aws credentials are saved and 'us-east-1' has been
   selected as the default region (use `aws configure`).

#. Place the private SSH key `id_raiden_testnet` into the `keys` directory

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


Force recreation of a specific resource
***************************************

If for some reason a specific resource needs to be recreated (for example if
a host is not reachable via ssh anymore) terraform can be instructed to do so
by using the following command::

    terraform taint aws_instance.node_raiden.95

This will cause the host resource to be "tainted" which in turn will cause it
to be recreated during the next run of `terraform apply` (or `make up`).

Updating a specific service
***************************

All docker images will automatically be recreated by running `make` however if
only a specific one should be updated (for example Raiden) the following
commands can be used::

    make docker-push-raiden
    ansible-playbook playbook-testnet.yml

In case of Raiden the repository and branch to use can be configured via
docker build ARGs. By default they point to master @ raiden-network/raiden.
For example::

    REPO=somename/raiden BRANCH=somebranch make docker-push-raiden

The Raiden dockerfile will automatically detect changes to the configured repo
and branch and rebuild accordingly.

Generally a complete rebuild of the Dockerfiles can be forced with::

    NOCACHE=1 make docker-push-<image>


Remove datadir
**************

Sometimes it may be necessary to remove the data directories. This can be
done with the following commands::

    ansible-playbook -t raiden playbook-remove_datadir.yml
    ansible-playbook -t eth playbook-remove_datadir.yml

Be sure to include the type with `-t <type>`, otherwise both the eth node and
raiden datadirs will be removed forcing a (lengthy) resync.


Reboot nodes
************

Sometimes it may become necessary to reboot the hosts of the Raiden nodes.
This can be done with::

    ansible -a "sudo reboot" role_raiden


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
