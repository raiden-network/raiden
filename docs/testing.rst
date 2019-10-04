How is Raiden tested.
#####################

Raiden tests are split into these categories. The following categories are
ordered from the faster and easier to debug to the slower and harder to debug:

- Unit tests: A collection of fast tests that do not require external services
  to run. Because these tests don't require any services nor threads to run,
  they don't have problems with flakyness and are easy to debug. They are
  located under ``raiden/tests/unit``.
- Property tests: These tests use randomly generated events. These tests are
  important ensure the system does not break when an unexpected series of
  events happen. Because of the architecture used by the project these tests
  are deterministic and do not require threads, therefore they are not flaky,
  but can be harder to debug because of their random nature. These tests are
  located under ``raiden/tests/fuzz``.
- Smoketest: This is a quick self contained test, that can be ran by a user or
  prior to the integration tests, to ensure the basics are working properly. It
  will start a private chain, the necessary infrastructure for the transport
  layer, deploy the smart contracts, start a Raiden instance and interact with
  the blockchain. This test is available as a command line command, and it's
  entry point is under ``raiden/ui/cli.py``.
- Integration tests: These are long running tests, that require external
  services to run. Integration tests are slower to run, they have to start a
  local private blockchain, a local transport infrastructure, multiple Raiden
  nodes, and the REST API for these nodes. A fresh set of smart contracts are
  deployed into this private chain, including Tokens and Raiden's smart
  contracts. These tests are important to make sure Raiden will work as
  expected with the Ethereum clients, however because they orchestrate multiple
  systems they are considerably slower than the previous categories,
  susceptible to flakyness, and harder to debug. These tests are located under
  ``raiden/tests/integration``.
- Scenario tests: These tests run multiple times against the available
  testnets. They exercise the Raiden nodes through the available REST API, in
  the same way a user application would. These tests are important to test the
  system against real life conditions (using the internet). These tests use the
  scenario-player utility, and the scenarios are available under
  ``raiden/tests/scenarios``.

Unit tests
==========

Unit tests are deterministic, single threaded, and side-effect free. Because
these tests don't interact with other systems there isn't any orchestration nor
synchronization, so the tests cannot be flaky and are easy to debug.

This the preferred type of test for business logic, and should always be the
preferred type of test to add to Raiden's test suite.

Integration Tests
=================

These tests exist to make sure that Raiden works properly with the other
systems. Including the Ethereum client, Matrix, and the services for path
finding and monitoring channels.

These tests are written in python and rely heavily on the pytest fixture
system. This is necessary because these tests will run multiple Raiden nodes in
a single process, exchange messages, and assert on the expected state of each
individual node.

Here is an overview of the fixture system:

- Configuration variables are defined in ``raiden/tests/fixtures/variables``.
  This file contains the default settings for a test. These settings can be
  overwritten by the ``pytest.mark.paremetrize`` decorator to change the test
  environment.  Good examples are the ``number_of_nodes`` which configures how
  many Raiden nodes should be started for the test, ``number_of_channels``
  which configure how many channels each of these nodes should have at the
  start of the test.
- The fixtures responsible to start a private chain are defined in
  ``raiden/tests/integration/fixtures/blockchain.py``. These will start a new
  private chain, either ``geth`` or ``parity``, with
  ``blockchain_number_of_nodes`` nodes. This private chain will have one
  prefunded account for each Raiden node, which allows these nodes to send
  on-chain transactions.
- The fixtures responsible to deploy the smart contracts are defined in
  ``raiden/tests/integration/fixtures/smart_contracts.py``. These fixtures
  depend on the private chain, and will deploy the necessary Raiden and Token
  Smart Contracts for the test.
- The fixtures responsible to start the transport are defined in
  ``raiden/tests/integration/fixtures/transport.py``. These fixtures will
  configure a local cluster of Matrix servers to run the tests.
- The fixtures responsible to start the raiden nodes and open the initial
  channels are defined in
  ``raiden/tests/integration/fixtures/raiden_network.py`` . These fixtures
  depend on both the previous fixtures, the private blockchain, the smart
  contract, and the transport fixtures. The raiden network fixtures will then
  create the Raiden apps and open the necessary channels for the test.

Which of the above fixtures are used depends on the test function, and it is
determined by pytest through its fixture system. A test that uses a
raiden_network fixture will have a fresh set of matrix servers, a new private
chain with newly deployed smart contracts, and running Raiden nodes with open
channels, ready to do transfers.

Because of all the moving parts, there are a few important things that have to
be kept in mind while writting a test:

- If a failure is not expected, it should make the test fail. In order to
  achieve this all tests are executed by a call to ``raise_on_failure``, which
  monitors all the Raiden nodes, and if any unexpected exception is raised on
  one of these nodes, the test fails. This works because all the spawned
  threads are monitored, and unhandled exceptions are always propagated in the
  code base.
- Each individual system may hang for different reasons. The teardown of the
  blockchain can hang while waiting for the sockets to close, the integration
  test may hang because a bug (e.g. deadlocks, missing events, race conditions,
  etc.). Because it is important to be careful while watching for events and
  setting proper timeouts.
