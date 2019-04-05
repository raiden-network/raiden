:orphan:

.. _nix_development_setup:

Dev environment with nix and direnv
===================================

Install nix
-----------

Install the ``nix`` package manager, by running

::

   curl https://nixos.org/nix/install | sh

or better, verify integrity of the installer script first according to
https://nixos.org/nix/download.html.

If you would like to set up python manually run

::

   nix-shell nix/shell.nix

from the project root and ``nix`` will install all system dependencies
and make them available in your current shell. Then continue with the
:ref:`Installation from source <installation_from_source>` section.

You can also let `direnv <https://direnv.net/>`__ take care of
activating the ``nix`` shell and a python virtual environment for you.

Install direnv
--------------

Install ``direnv`` for instance by running

::

   nix-env -iA nixpkgs.direnv

Hook it into your shell

::

   eval "$(direnv hook bash)"  # for bash
   eval "$(direnv hook zsh)"   # for zsh
   eval (direnv hook fish)     # for fish

and add that line into ``~/.bashrc`` (or equivalent) for future use if
desired.

Activate direnv
---------------

Run

::

   ln -s nix/envrc-nix-python .envrc
   direnv allow

which will

1. Fetch all system dependencies with ``nix`` if necessary.
2. Activate the ``nix`` shell.
3. Create a python virtualenv for the project if necessary.

Now each time you ``cd`` into this directory, ``direnv`` will activate
this environment.

Run

::

   pip install -r requirements-dev.txt -c constraints-dev.txt -e .

to install the dependencies in ``requirements-dev.txt`` and ``raiden``
itself.
