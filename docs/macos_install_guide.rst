:orphan:

.. _macos_development_setup:

Development Setup on macOS
==========================

.. :highlight: bash

The following instructions will guide you from a clean installation of macOS to a working source checkout of raiden. Make sure that you are on OSX 10.12 or higher. This is needed since raiden uses the MONOTONICK_CLOCK_RAW attribute as seen `here <https://github.com/raiden-network/raiden/issues/4679#issuecomment-526128654>`__

#. Install C/C++ compiler infrastructure::

    $ xcode-select --install

   * Click "Install" then "Agree", wait for installation to complete

#. Install `Homebrew`_ (a macOS package manager)::

    $ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

   * Follow the instructions

#. Obtain a MONOTONIC_CLOCK_RAW compatible python version

   The precompiled Python versions for download on python.org are built on a too old macOS version which are not compatible with ``MONOTONIC_CLOCK_RAW``. As such you will have to manually obtain a python binary that supports it. There are three ways to achieve this:

   * Use brew
   * Use `pyenv <https://realpython.com/intro-to-pyenv/>`__
   * Use `pythonz <https://github.com/saghul/pythonz>`__

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
