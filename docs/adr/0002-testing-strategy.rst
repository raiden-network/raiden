[0002] Better testing framework for entire Raiden suite (client, MS and PFS)
*********************************************************************

* **Status**: proposed
* **Deciders**: @czepluch, @stefante
* **Date**: 2019-11-03 (last updated)


Context and Problem Statement
-----------------------------

@rakanalh @karlb @LefterisJP and @czepluch had a meeting to discuss testing moving forward. More precisely how we can test the client together with the MS and PFS. Most of the discussion was focused on whether it makes sense to continue to support the scenario player and update it to support the third party services. Currently the SP is good for testing happy cases, but it is not easy to debug when errors occur and it doesn't allow for introspection in the same way as pytest does. On the other hand, the current way that the integration tests work by spinning up a new blockchain per test is very inefficient. It's also quite intimidating for people new to the project or less experienced to grasp how the integration tests work.
Based on these short comings of the current two solutions, we discussed what could be done to create a setup that solves both problems.

.. Decision drivers is optional
Decision Drivers
-------------------

* Lack debug options for scenario player
* Slow to spin up a fresh blockchain for every integration test
* Duplicated tests between integration tests and SP
* Make it easier for people new to the project or less experienced people to write tests
* Have a way of testing all Raiden components

Considered Options
---------------------

* **Option1:** New repo that integrate the client with the MS/PFS with rewritten fixtures that only spins up one blockchain per test suit session. `Link to meeting discussing this <https://github.com/raiden-network/team/issues/357>`_
* **Option2:** Stick with things as they are and focus on adding functionality to the scenario player

Decision Outcome
-------------------

**TBD**

.. Pros and cons are optional
Pros and Cons of the Options
----------------------------

[option 1]
~~~~~~~~~~

* Good, because writing what we currently call integration tests will be easier
* Good, because there will be one blockchin spun up per testing session instead of per test
* Good, because we will use pytest and make debugging easier than it currently is with the SP
* Good, because we will enforce a "language" that interacts with the API server instead of python functions
* Good, because we don't need to maintain the SP anymore
* Bad, because it will be quite some effort to rewrite all the fixtures to use one blockchain per session

[option 2]
~~~~~~~~~~

* Good, because we don't have to create a new repo and rewrite the fixtures
* Bad, because we have to maintain the SP and write scenarios
* Bad, because the SP offer limited flexibility
* Bad, because debugging scenarios that fail can be very difficult
* Bad, because it's difficult to get started writing integration tests at the moment
