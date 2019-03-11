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


class RESTAPITimeout(RESTAPIError):
    pass


class MultipleTaskDefinitions(ScenarioError):
    """Several root tasks were defined in the scenario configuration."""


class InvalidScenarioVersion(ScenarioError):
    pass


class UnknownTaskTypeError(ScenarioError):
    pass


class MissingNodesConfiguration(ScenarioError, KeyError):
    """Could not find a key in the scenario file's 'nodes' section."""


class ScenarioAssertionError(ScenarioError):
    pass
