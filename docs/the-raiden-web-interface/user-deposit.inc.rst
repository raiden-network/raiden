.. _webui_udc:

Manage UDC funds
================

On the top bar you can click the button next to the **"UDC Deposit"** to open a dialog for managing your funds in the User Deposit Contract.
This dialog allows you to perform deposits and withdrawals. 
It will show you the amount of Raiden Network Tokens (RDN) you have on-chain, which are necessary for deposits.

For a deposit, click the **"Deposit"** button and enter the amount of RDN tokens you would like to have in the UDC.
This will trigger all necessary on-chain transactions.

For a withdrawal, you first need to click **"Plan Withdrawal"**.
After entering the amount of tokens you would like to withdraw, you have to wait for at least 100 blocks on-chain before you can perform the actual withdrawal.
When these 100 blocks have passed, a **"Withdraw"** button will show up.
Clicking it will trigger another on-chain transaction.

.. note::

   **What is the User Deposit Contract (UDC)?**

   The UDC is a smart contract where you deposit RDN (Raiden Network Tokens) for later paying the :doc:`Raiden Services <../raiden_services>`.
   For sending a :ref:`mediated transfer <mainnet_tutorial_mediated_payments>` it is even necessary to have RDN tokens in the UDC.

