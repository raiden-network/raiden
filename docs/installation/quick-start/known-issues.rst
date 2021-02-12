Handle Limitations
==================

Internal Server Error
---------------------

The Raiden Wizard will display an **Internal Server Error** if an
invalid project ID is provided. To solve this you have to `manually
delete the configuration
file <known-issues.md#delete-configuration-files-1>`__ that got created.

Stop Raiden from running
------------------------

The Wizard does not provide a way of shutting down the Raiden node. You
have to cancel the process to stop Raiden.

{% tabs %} {% tab title="Mac" %} Use the activity monitor for cancelling
Raiden. {% endtab %}

{% tab title="Linux" %} Use any Linux process manager for stopping
Raiden. {% endtab %} {% endtabs %}

Delete configuration files
--------------------------

You might want to delete configuration files if the wizard is taking a
long time to start or if an invalid project ID has been provided and the
wizard won't start at all.

{% tabs %} {% tab title="Mac" %} Navigate to the following folder:

.. code:: bash

   /Users/<username>/.local/share/raiden/

Delete desired **.toml** file/files. {% endtab %}

{% tab title="Linux" %} Navigate to the following folder:

.. code:: bash

   /home/<username>/.local/share/raiden/

Delete desired **.toml** file/files. {% endtab %} {% endtabs %}
