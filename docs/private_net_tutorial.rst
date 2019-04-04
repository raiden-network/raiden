Raiden on Private Network Tutorial
##################################

Introduction
============

This tutorial shows how to run Raiden on a private network, using the ``master`` branch (this is useful when you are working on a pull-request).

Creating a Virtual Environment
==============================

In a shell, run

.. code:: bash

 $ rm -rf priv_chain
 $ mkdir priv_chain
 $ cd priv_chain
 $ virtualenv -p python3.7 env
 $ source env/bin/activate

You should now be in the virtual environment, where all Python package installations are separately managed.

Now the command prompt should look like:

.. code:: bash

 (env) $


Install Raiden and dependencies
===============================

.. code:: bash

 (env) $ pwd
 <snip>/priv_chain
 (env) $ git clone https://github.com/raiden-network/raiden
 (env) $ cd raiden
 (env) $ pip install -r requirements.txt -c constraints.txt -e .

Launch a private network
========================

Create an account
-----------------

Start mining
------------

Figure out the contract version
===============================

Deploy contracts
================
