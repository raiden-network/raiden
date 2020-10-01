from raiden.exceptions import RaidenValidationError


class ChannelNotFound(RaidenValidationError):
    """Raised when a provided channel via the REST api is not found in the
    internal data structures.
    """


class NonexistingChannel(RaidenValidationError):
    """The requested channel does not exist.

    This exception can be raised for a few reasons:

    - The user request raced and lost against a transaction to close/settle the
      channel.
    - The user provided invalid values, and the given channel does not exist.
    """
