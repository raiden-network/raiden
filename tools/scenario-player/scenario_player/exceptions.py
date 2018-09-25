class ScenarioError(Exception):
    pass


class ScenarioTxError(ScenarioError):
    pass


class TokenRegistrationError(ScenarioTxError):
    pass


class ChannelError(ScenarioError):
    pass


class TransferFailed(ScenarioError):
    pass


class NodesUnreachableError(ScenarioError):
    pass


class RESTAPIError(ScenarioError):
    pass


class RESTAPIStatusMismatchError(ScenarioError):
    pass


class UnknownTaskTypeError(ScenarioError):
    pass


class ScenarioAssertionError(ScenarioError):
    pass
