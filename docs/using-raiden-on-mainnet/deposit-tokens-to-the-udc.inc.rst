Deposit Tokens to the UDC
=========================

This section will describe how to manually add Raiden Network Tokens to
the UDC by:

1. Approving the UDC to use RDN
2. Depositing RDN to the UDC

Approving the UDC to use RDN
----------------------------

We need to approve a value of Raiden Network Tokens that the UDC is
allowed to spend. To do so:

1. Visit the `RDN token on
   Etherscan <https://etherscan.io/address/0x255Aa6DF07540Cb5d3d297f0D0D4D84cb52bc8e6#writeContract>`__.
2. Go to the "**approve"** field under "**Write Contract"**.
3. Enter ``0x1c62fF66aF8aaD410065E02338F5bFbbe23e1f10`` (the mainnet UDC
   address) as argument for **"_spender"**.
4. Enter an amount of ``100000000000000000000`` (corresponding to 100
   RDN) as argument for **"_value"**.
5. Click on **"Write"** to approve.

Depositing RDN to the UDC
-------------------------

Once we have approved an RDN amount all that reamins is for us to
deposit some tokens to the UDC.

1. Visit the `UDC on
   Etherscan <https://etherscan.io/address/0x1c62fF66aF8aaD410065E02338F5bFbbe23e1f10#writeContract>`__.
2. Go to the **"deposit"** field under **"Write Contract"**.
3. Enter the address of the Raiden node you want to use as argument for
   **"beneficiary"**.
4. Enter an amount of e.g. ``100000000000000000000`` (corresponding to
   100 RDN) as argument for **"new_total_deposit"**.
5. Click on **"Write"** to make the deposit.
