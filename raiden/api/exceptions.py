from raiden.exceptions import RaidenValidationError


class ChannelNotFound(RaidenValidationError):
    """ Raised when a provided channel via the REST api is not found in the
    internal data structures.
    """
