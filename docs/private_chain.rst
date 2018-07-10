Private chain creation tutorial
===============================

Running Raiden on a private chain can be less time consuming and more
efficient in the sense that it takes up lesser space on your local hard
drive since because block headers from your testnet of choice do not
need to be stored locally (thus avoiding days spent synchronizing these
headers). The steps are fairly simple and are very useful if you are a
developer:

1. **Create a new directory** Enter the command
``mkdir private_net``. This will create a new directory called
“private_net”. Enter this new folder using ``cd private_net`` and make a
sub-folder called “data” using ``mkdir data``. Enter “data” using
``cd data``.

2. **Create a new genesis file** This step describes the
first block of your chain with various settings in a JSON file. Create a
new file using the command ``touch myGenesis.json``. Open this file with
a file editor of your choice (Atom, vim, etc.) and enter the following
code:

   `{“config”: { “chainId”: 1994, “homesteadBlock”: 0, “eip155Block”: 0,“eip158Block”: 0, “byzantiumBlock”: 0 }, “difficulty”: “400”,“gasLimit”: “20000000”, “alloc”: {“7b684d27167d208c66584ece7f09d8bc8f86ffff”: { “balance”:“100000000000000000000000” },“ae13d41d66af28380c7af6d825ab557eb271ffff”: { “balance”:“120000000000000000000000” } } } `

This is your genesis code. Now save this and go back to your "private_net" folder using `cd ../`. Note that the `gasLimit` in this file is very high. This is to give you enough wiggle room to deploy complex contracts on the network.

3. **Initialize genesis block** I complete this step using the
   go-ethereum (geth) client. Go back to your “private_net” folder using
   ``cd ../`` and create a new folder called “ethData” using the command
   ``mkdir ethData``. This directory will be used by geth to store data.
   Now, to initialize the genesis block enter
   ``geth console --data-dir "./ethData" init "./data/myGenesis.json"``.
   This is what your terminal screen should look like at this point:
   .. image:: images/tutorial_images/1.png :width: 900px

4. **Create a new geth account** While in the geth console, enter
   ``personal.newAccount("Enter Desired Password")``. Obviously you
   should use something better for your password. Do not lose this, you
   will need this every time you run geth in the future. This is what
   your screen should look like now:
   .. image:: images/tutorial_images/2.png :width: 900px
   The hexadecimal value you see here is your account’s address on the
   network. Think of it as your username for your geth account. You
   can create multiple geth accounts this way.

5. **Relaunch geth console and open RPC endpoint** Stop the geth console
   by entering ``exit``. Then enter
   ``geth console --networkid 4555 --mine --minerthreads 1 --datadir "./ethData"  --nodiscover --port "30303" --nat "any" --unlock 0 --ipcpath "~/Library/Ethereum/geth.ipc"``
   to start your geth client inmining mode with the console. It will prompt you to enter a password. Note that this is the password for the account that you created that is at index 0 in the list of accounts. This will start mining blocks on a private network with ID 4555. Once the mining starts, this is what your screen should look like:
   .. image:: images/tutorial_images/3.png :width: 900px
   Soon you will see your geth client configuring the DAG, and then your blocks will be mined. It should look like this:
   .. image:: images/tutorial_images/4.png :width: 900px

And that's about it! You have now created a private blockchain. You can use the network ID that you started your geth client with to start a new Raiden instance on your computer. Happy developing!



