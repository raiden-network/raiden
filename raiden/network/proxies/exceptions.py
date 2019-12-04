from raiden.exceptions import RaidenRecoverableError


class MintFailed(RaidenRecoverableError):
    """Raised if calling the mint function failed."""

    pass
