Raiden Client Python Dependency Management
==========================================

Usage
-----

Add a new dependency
~~~~~~~~~~~~~~~~~~~~

- Insert the new package into the appropriate ``.in`` file.

  - Optionally a version constraint can be added here (e.g. to prevent a known
    incompatibility with a newer version). This should be done as little as possible since
    such constraints can prevent successful dependency resolution.
- Run::

    requirements/deps compile

  - This will only resolve the new package and not change any of the already pinned dependencies.

    - The only exception to that is if the new package has a dependency to a newer version of
      an already pinned dependency.

- Commit the changed ``.in`` and ``.txt`` files.

Upgrade an existing dependency
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Run::

    requirements/deps upgrade <package-name>[<version-spec>] [<package-name>[<version-spec> ...]

  - As ``compile`` this will only affect the named packages unless it's necessary to upgrade other
    packages to solve dependencies.
- Commit the changed ``.in`` and ``.txt`` files.

Upgrade all dependencies
~~~~~~~~~~~~~~~~~~~~~~~~

- Run::

    requirements/deps upgrade

- Commit the changed ``.in`` and ``.txt`` files.


.. note:: This should be used with care since 'blindly' upgrading all dependencies may have
          unintended consequences.

          Testing the outcome with the ``--verbose`` and ``-dry-run`` options may be useful.

Syncing the local venv to the requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All the commands mentioned above only operate on the requirement and template files.

To actually install / upgrade one's local venv you can use the ``install-dev`` make target::

    make install-dev

This will run ``pip-sync`` (see below) which will install/upgrade/remove packages from the venv
in order to match the dependencies exactly.

.. note:: This means any additional one-off packages you may have installed into your venv will
          get removed.

          To prevent this you can add any development packages you'd like to keep available
          into the ``requirements/requirements-local.txt`` file (which is excluded from git).


Underlying tools
----------------

We use pip-tools_ via a custom wrapper (more on that below) to manage the Python package
dependencies.

.. _pip-tools: https://github.com/jazzband/pip-tools

``pip-tools`` consists of two cli utilities, ``pip-compile`` and ``pip-sync``.

This guide is mainly concerned with ``pip-compile``.


``pip-sync``
~~~~~~~~~~~~

``pip-sync`` is used by the ``install`` and ``install-dev`` Makefile targets to ensure the
local venv exactly matches the packages and versions listed in the corresponding
``requirements*.txt`` files, installing / upgrading any missing packages and
removing any superfluous ones.

``pip-compile``
~~~~~~~~~~~~~~~

``pip-compile`` reads requirement template files (``*.in``) and produces requirement files
(``*.txt``) that contain the recursively expanded dependencies pinned to exact versions.


For Raiden we interact with ``pip-compile`` via a custom wrapper ``requirements/deps``
(``tools/pip-compile-wrapper.py``) that adds support for handling dependencies between requirement
files.

`This blog post`_ explains the underlying idea of a pip-tools workflow with dependencies.
Our wrapper tool goes further than the Makefile proposed in that post though.

.. _`This blog post`: https://jamescooke.info/a-successful-pip-tools-workflow-for-managing-python-package-requirements.html
