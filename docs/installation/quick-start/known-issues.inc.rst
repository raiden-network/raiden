Handle Limitations
##################

Internal Server Error
=====================

The Raiden Wizard will display an **Internal Server Error** if an
invalid project ID is provided. To solve this you have to :ref:`manually
delete the configuration
file <wizard_delete_config>` that got created.

Stop Raiden from running
========================

The Wizard does not provide a way of shutting down the Raiden node. You
have to cancel the process to stop Raiden.

**MacOS:** Use the activity monitor for cancelling
Raiden.

**Linux:** Use any Linux process manager for stopping
Raiden.

.. _wizard_delete_config:

Delete configuration files
--------------------------

You might want to delete configuration files if the wizard is taking a
long time to start or if an invalid project ID has been provided and the
wizard won't start at all.

Navigate to the following folder:

.. code:: bash

   MacOS: /Users/<username>/.local/share/raiden/
   Linux: /home/<username>/.local/share/raiden/

Delete desired **.toml** file/files.
