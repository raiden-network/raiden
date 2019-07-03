[Python Package Dependency Management]
********************************************

* **Status:** proposed
* **Deciders:** TBD
* **Date:** 2019-06-18

Context and Problem Statement
-----------------------------

We as a team have been struggling with dependency management for a while now.
Our current approach ('manual' requirements + pip constraints files) is cumbersome and error prone
especially in case of dependency package version upgrades.
Generally better tool support was seen as a solution to the issue.

Decision Drivers
----------------

* The Process of upgrading a Python package dependency is an error prone, cumbersome and manual
  process
* There were multiple occasions of failed dependency upgrades leading to failed CI builds and
  downstream incompatibilities

Considered Options
------------------

* pip-tools_
* poetry_
* pipenv_

.. _pip-tools: https://github.com/jazzband/pip-tools
.. _poetry: https://poetry.eustace.io
.. _pipenv: https://pipenv.org

Decision Outcome
----------------

``pip-tools`` was chosen after a discussion between @hackaugusto, @konradkonrad, @palango and
@ulope as it currently seems to be the least disruptive and most well-used tool available.
Medium term ``poetry`` might become the preferred solution but didn't appear mature enough currently.

Pros and Cons of the Options
----------------------------

``pip-tools``
~~~~~~~~~~~~~

Currently the most mature tool.

* Pros

  * Small scope, only manages dependencies
  * (Relatively) easy to understand operation model
  * Stable with a long history of being maintained
  * Better dependency solver than pip (which doesn't have one)

* Cons

  * No built-in support for dependencies between various requirement types (e.g. prod, dev).
    Requiring a custom wrapper tool.
  * CLI isn't very intuitive

``poetry``
~~~~~~~~~~

Looks to be a good candidate to switch to in the medium future.

* Pros

  * Very polished cli
  * Handles the complete package life-cycle including optional venv management
  * Proper dependency solver

* Cons

  * Still very new with some bugs and some usage types not supported (yet)
  * Very much a departure from the established 'way of doing things'
  * Dependency resolution can currently be very slow

``pipenv``
~~~~~~~~~~

Similar in concept to poetry, yet seems to be not a stable tool to build upon.

* Pros

  * ?

* Cons

  * Also a very new tools
  * Many reports of arbitrary breakage with minor upgrades
  * Dependency resolution appears not to be stable
