:orphan:

.. _macos_development_setup:

Development Setup on macOS
==========================

.. :highlight: bash

The following instructions will guide you from a clean installation of macOS to a working source
checkout of raiden.

#. Install C/C++ compiler infrastructure::

    $ xcode-select --install

   * Click "Install" then "Agree", wait for installation to complete

#. Install `Homebrew`_ (a macOS package manager)::

    $ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

   * Follow the instructions

#. Install system packages needed for :code:`raiden` and its dependencies::

    $ brew install automake gmp leveldb libffi libtool openssl pkg-config

#. Install `pip`_ (a Python package manager)::

    $ sudo easy_install pip

#. Install `virtualenv`_::

    $ sudo pip install virtualenv

#. Create a virtualenv for raiden (requires python3.7)::

    $ virtualenv --python=python3.7 venv-raiden

#. "Activate" the virtualenv::

    $ source venv-raiden/bin/activate

#. Clone the raiden repository::

    $ git clone https://github.com/raiden-network/raiden.git

#. Install the dependencies and make raiden available inside the virtualenv::

    $ cd raiden
    $ make install-dev

    # or alternatively, manually:
    # pip install -c constraints-dev.txt -r requirements-dev.txt -e .


Now you have a working source installation of Raiden.
To actually use it you also need the solidity compiler solc_ and an `Ethereum client`_.
Both can be installed as follows::

    $ brew tap ethereum/ethereum
    $ brew install solidity ethereum

The installation should now be complete. To ensure your setup is working correctly you can use the
:code:`smoketest` command::

    $ raiden smoketest


:ref:`Return to the installation guide <running_raiden>`

.. _Homebrew: http://brew.sh
.. _pip: https://pip.pypa.io/en/stable/
.. _virtualenv: https://virtualenv.pypa.io
.. _solc: https://github.com/ethereum/solidity
.. _Ethereum client: https://github.com/ethereum/go-ethereum/
