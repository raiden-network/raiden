Running integration tests with different transport protocols
============================================================

Raiden can be run with two different underlying transport protocols, UDP and Matrix. Therefore tests that depend on the transport layer (all of them are integration tests) come in two versions.

The pytest option ``--transport=none|udp|matrix|all`` can be used to specify which versions of the test to run. By default, only the UDP versions of the tests are run, since the Matrix versions require the local installation of the `Synapse <https://matrix.org/docs/projects/server/synapse.html>`_ Matrix server.

Installing Synapse for Matrix tests
-----------------------------------

Synapse requires Python 2.7 and SQLite. Please run ``tools/install_synapse.sh`` to generate a standalone binary for it, or follow these steps:

- create a Python 2 virtualenv, install Synapse in it with pip, and
- create a script that runs Synapse as a python module, using the configuration file in ``raiden/tests/test_files``.

The script will then be called by the test suite during setup. The path can be specified with the ``--local-matrix`` option, it defaults to ``.synapse/run_synapse.sh`` in Raiden's main directory.
