==========
Pathfinder
==========

Pathfinding service for the Raiden Network

Developing
----------

Ready to contribute? Here's how to set up `raiden-pathfinding-service` for local development.

1. Fork the `raiden-pathfinding-service` repo on GitHub.
2. Clone your fork locally::

    $ git clone git@github.com:your_name_here/raiden-pathfinding-service.git

3. Install your local copy into a virtualenv. Assuming you have virtualenvwrapper installed, this is how you set up your fork for local development::

    $ mkvirtualenv raiden-pathfinding-service
    $ cd raiden-pathfinding-service/
    $ python setup.py develop

4. Create a branch for local development::

    $ git checkout -b name-of-your-bugfix-or-feature

   Now you can make your changes locally.

5. When you're done making changes, check that your changes pass flake8 and the
   tests, including testing other Python versions with tox::

    $ make lint
    $ python setup.py test or py.test

   To get flake8, just pip install them into your virtualenv.

6. Commit your changes and push your branch to GitHub::

    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

7. Submit a pull request through the GitHub website.

Tips
----

To run a subset of tests::

$ py.test tests.test_pathfinder

