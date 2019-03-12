
Features
========

The final installer package should offer the following features:

    - Restartable

        The installer is restartable, as it tracks steps already taken and continues
        from the last successfully executed step.

    - Offers Modification of existing installation

        If it was run successfully before, it offers options to exent the current
        installation, for example if a Testnet configuration was already installed,
        we offer the option to setup a mainnet configuration.

    - Offers installing updates

    - Full Stack Installation

        The installer fetches and installs a complete stack for raiden development;
        this includes:

            - Fetching the latest Raiden binary from our DigitalOcean space.

            - Setting up the Raiden Network Configuration, including checking
                Safe-Use-Requirements.

            - Setting up an Ethereum client, including downloading required files
                and installing them, if they are not present.

            - Setting up a dedicated account for the raiden client.

            - Funding the account with ether.

            - Acquire tokens from a faucet or minting them.

            - Setting up a symbolic link & desktop icon.

            - Launching the stack, connecting to the token network, and starting
                up Raiden.



Reference:

    https://github.com/raiden-network/raiden/issues/3525

