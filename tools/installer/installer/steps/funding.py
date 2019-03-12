from installer.utils import is_testnet


def request_testnet_ether(account: str, network: str):
    """Request ether for the given `account`

    TODO: This is a stub.
    """
    return account, network


def fund_mainnet_account(account):
    """Magically fund your main net account out of thin air.

    ..or something.

    TODO: This is a stub.
    """
    return account


def fund_account(network, account):
    if is_testnet(network):
        request_testnet_ether(account, network)
    else:
        if create_account:
            fund_mainnet_account(account)
        else:
            # Do nothing - existing accounts should be funded by the user.
            pass
