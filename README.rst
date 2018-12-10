==========
Pathfinder
==========

Pathfinding service for the Raiden Network

Running
-------
To run the PFS follow the steps below:

1. Fork the `raiden-pathfinding-service` repo on GitHub.

2. Clone your fork locally::

    $ git clone git@github.com:your_name_here/raiden-pathfinding-service.git

3. Install your local copy into a virtualenv. Assuming you have virtualenvwrapper installed, this is how you set up your fork for local development::

    $ mkvirtualenv raiden-pathfinding-service
    $ cd raiden-pathfinding-service/
    $ python setup.py develop

4. Now you can run the PFS locally::

    $ pathfinder --eth-rpc http://localhost:8545

Developing
----------

Ready to contribute? Here's how to set up `raiden-pathfinding-service` for local development. Follow setps 1 to 3 from above.

1. Create a branch for local development::

    $ git checkout -b name-of-your-bugfix-or-feature

   Now you can make your changes locally.

2. When you're done making changes, check that your changes pass flake8 and the
   tests, including testing other Python versions with tox::

    $ make lint
    $ python setup.py test or py.test

   To get flake8, just pip install them into your virtualenv.

3. Commit your changes and push your branch to GitHub::

    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

4. Submit a pull request through the GitHub website.
