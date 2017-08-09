Webui tutorial
##############

In order to quickly give people an overview and idea of what the Raiden Developer Preview is capable of, a simple web application has been created. This application utilizes the :doc:`Raiden REST API endpoints <rest_api>` to allow the user to interact with tokens networks, transfer tokens, see the current status of open channels along with closing and settling channels to name some of the functionalities. For a more specific guide of the API itself see the :doc:`API Walkthrough <api_walkthrough>`.

The main focus of the web application is to display functionality and not to look pretty. Should you however want to make it pretty, don't hesitate to create a `pull request <https://github.com/raiden-network/raiden/pulls>`_.


Running the web application
---------------------------
There are a few simple steps that needs to be carried out in order to run the Raiden web application. Firstly, a Raiden node needs to be setup. See :doc:`overview_and_guide` for instructions on this.

The only dependency needed to run the web application is `node.js <https://docs.npmjs.com/getting-started/installing-node>`_.

Once a Raiden node is up and running and node.js has been installed, it is quite easy to start the web application::

    cd raiden/ui/web

Followed by::

    npm install

And then to run the application simply do::

    npm start

Now all that is left to do is to navigate to `localhost:4200 <localhost:4200>`_ and interaction with Raiden through a web application can begin.


The landing page
------------------
The first thing that will meet the user is the landing page. The landing page is meant to give a short introduction to Raiden and link to some relevant documentation. Furthermore it is also meant to provide an overview of some interesting statistics about Raiden.

Below is a screenshot of the landing page.

.. image:: images/raiden_webui_landing_page_screenshot.png
    :alt: Raiden web app landing page

One last thing that might be interesting to note is that the address of the Raiden node is always displayed in the top bar.

Channels
-------------
    * status of open channels
    * open new channels
    * monitor events


Tokens
----------
    * see token networks
    * register token
    * join token network
    * make token swap
    * leave token network
