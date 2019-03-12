

def acquire_token(network: str, token: str) -> None:
    """Acquire the given `token` on the given `network`.

    TODO: This is a stub.
    """


def token_acquisition(network, is_testnet):
    """Execute the token acquisition step.

    TODO: This is a stub.
    """
    if is_testnet(network):
        # TODO: User input require input validation.
        token = input('Specify a token to acquire:')
        acquire_token(token)
    else:
        # Skipping token acquisition for Main network.
        pass

