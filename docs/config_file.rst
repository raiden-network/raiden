Raiden Config File
##################

Raiden supports reading configuration parameters from a configuration file.

Location
--------

The default location is ``<datadir>/config.toml`` (where datadir defaults to ``~/.raiden``).

It is possible to override the ``datadir`` in the config file but please be aware that at that point
the config file will already have been loaded from the default location and therefore won't be
re-read from the 'new' datadir.

Precedence
----------

The precedence order in which configuration option values are applied is as follows (high to low):

#. Option given on the command line
#. Option read from the config file
#. Option default value (as seen in the output of ``raiden --help``)


Format
------

The config file uses the `TOML`_ format.

Option names may be quoted unless they contain punctuation in which case they must be.
Values except numbers must always be quoted. Both single or double quotes are acceptable.

Lines *starting* with a ``#`` are comments.

.. _TOML: https://github.com/toml-lang/toml


Parameter Naming
----------------

All parameters that can be given as command line options are also settable in the config file.
The name corresponds to the long option name without the leading double dash (``--``). For example
the CLI option ``--password-file`` would be called ``password-file`` inside the config file.

The only option deviating from this scheme is the `logging configuration`_ which is explained
below.


Logging Configuration
---------------------

Raiden allows configuration of the logging system using a concise syntax on the command line.
Inside the configuration file this is split out into a somewhat more expanded syntax.

The logging configuration is placed inside a section called ``[log-config]`` which each following
lines key representing the logger name and the value the log level.

Example::

    # CLI:
    --log-config ':debug,raiden.network:info'

    # Config file equivalent:
    [log-config]
    "" = "debug"
    "raiden.network" = "info"
