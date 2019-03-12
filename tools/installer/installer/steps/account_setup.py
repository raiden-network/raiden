import pathlib


def setup_account(client: pathlib.Path) -> Any:
    """Create a new account using the given client.

    TODO This is a stub.
    """
    return client


def account_setup(client):
    """Execute the account creation step.

    TODO This is a stub.
    """
    # Determine if we need to setup a new account for the user
    # TODO: User input require input validation.
    print(
        "\nPlease select one:"
        "   [1] Use existing Ethereum user account"
        "   [2] Create a new Ethereum account\n",
    )
    create_account = input("Your selection: [1]")

    if create_account:
        account = setup_account(client)
    else:
        account = input("Please specify the account to use:")

    return account
