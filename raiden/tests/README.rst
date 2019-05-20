Running integration tests with different transport protocols
============================================================

Raiden can be run with Matrix underlying transport protocols. Therefore tests that depend on the transport layer (all of them are integration tests) come in two versions.

The pytest option ``--transport=none|matrix`` can be used to specify which versions of the test to run. By default, only the UDP versions of the tests are run, since the Matrix versions require the local installation of the `Synapse <https://matrix.org/docs/projects/server/synapse.html>`_ Matrix server.
