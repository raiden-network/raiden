import pathlib
from collections.abc import Mapping
from typing import Any, Callable, Dict, List, Tuple, Union

import structlog
import yaml

from scenario_player.constants import SUPPORTED_SCENARIO_VERSIONS, TIMEOUT, NodeMode
from scenario_player.exceptions import (
    InvalidScenarioVersion,
    MissingNodesConfiguration,
    MultipleTaskDefinitions,
    ScenarioError,
)
from scenario_player.utils import get_gas_price_strategy

log = structlog.get_logger(__name__)


class NodesConfig(Mapping):
    """Thin wrapper around a Node configuration dictionary.

    Handles exceptions handling for missing values. Additionally, enables users
    to iter directly over the internal .nodes property, while also allowing
    key-based access to the original configuration dictionary.

    :param nodes_config: The node configuration as set in the scenario yaml.
    :param scenario_version: Version of the scenario yaml file.
    """

    def __init__(self, nodes_config: Dict, scenario_version: int = 1):
        self._config = nodes_config
        self._scenario_version = scenario_version

    def __getitem__(self, item):
        return self._config.__getitem__(item)

    def __iter__(self):
        return iter(self.nodes)

    def __len__(self):
        return len(self.nodes)

    @property
    def mode(self):
        if self._scenario_version == 2:
            try:
                mode = self._config['mode'].upper()
            except KeyError:
                raise MissingNodesConfiguration(
                    'Version 2 scenarios require a "mode" in the "nodes" section.',
                )
            try:
                return NodeMode[mode]
            except KeyError:
                known_modes = ', '.join(mode.name.lower() for mode in NodeMode)
                raise ScenarioError(
                    f'Unknown node mode "{mode}". Expected one of {known_modes}',
                ) from None
        return NodeMode.EXTERNAL

    @property
    def raiden_version(self) -> str:
        return self._config.get('raiden_version', 'LATEST')

    @property
    def count(self):
        try:
            return self._config['count']
        except KeyError:
            raise MissingNodesConfiguration('Must specify a "count" setting!')

    @property
    def default_options(self) -> dict:
        return self._config.get('default_options', {})

    @property
    def node_options(self) -> dict:
        return self._config.get('node_options', {})

    @property
    def nodes(self) -> List[str]:
        """Return the list of nodes configured in the scenario's yaml.

        Should the scenario use version 1, we check if there is a 'setting'.
        If so, we derive the list of nodes from this dictionary, using its
        'first', 'last' and 'template' keys. Should any of these keys be
        missing, we throw an appropriate exception.

        If the scenario version is not 1, or no 'range' setting exists, we use
        the 'list' settings key and return the value. Again, should the key be
        absent, we throw an appropriate error.

        :raises MissingNodesConfiguration:
            if the scenario version is 1 and a 'range' key was detected, but any
            one of the keys 'first', 'last', 'template' are missing; *or* the
            scenario version is not 1 or the 'range' key and the 'list' are absent.
        """
        if self._scenario_version == 1 and 'range' in self._config:
            range_config = self._config['range']

            try:
                start, stop = range_config['first'], range_config['last'] + 1
            except KeyError:
                raise MissingNodesConfiguration(
                    'Setting "range" must be a dict containing keys "first" and "last",'
                    ' whose values are integers!',
                )

            try:
                template = range_config['template']
            except KeyError:
                raise MissingNodesConfiguration(
                    'Must specify "template" setting when giving "range" setting.',
                )

            return [template.format(i) for i in range(start, stop)]
        try:
            return self._config['list']
        except KeyError:
            raise MissingNodesConfiguration('Must specify nodes under "list" setting!')

    @property
    def commands(self) -> dict:
        """Return the commands configured for the nodes."""
        return self._config.get('commands', {})


class Scenario(Mapping):
    """Thin wrapper class around a scenario .yaml file.

    Handles default values as well as exception handling on missing settings.

    :param pathlib.Path yaml_path: Path to the scenario's yaml file.
    """

    def __init__(self, yaml_path: pathlib.Path) -> None:
        self._yaml_path = yaml_path
        self._config = yaml.safe_load(yaml_path.open())
        try:
            self._nodes = NodesConfig(self._config['nodes'], self.version)
        except KeyError:
            raise MissingNodesConfiguration('Must supply a "nodes" setting!')

    def __getitem__(self, item):
        return self._config.__getitem__(item)

    def __iter__(self):
        return iter(self._config)

    def __len__(self):
        return len(self._config)

    @property
    def version(self) -> int:
        """Return the scenario's version.

        If this is not present, we default to version 1.

        :raises InvalidScenarioVersion:
            if the supplied version is not present in :var:`SUPPORTED_SCENARIO_VERSIONS`.
        """
        version = self._config.get('version', 1)

        if version not in SUPPORTED_SCENARIO_VERSIONS:
            raise InvalidScenarioVersion(f'Unexpected scenario version {version}')
        return version

    @property
    def name(self) -> str:
        """Return the name of the scenario file, sans extension."""
        return self._yaml_path.stem

    @property
    def settings(self):
        """Return the 'settings' dictionary for the scenario."""
        return self._config.get('settings', {})

    @property
    def protocol(self) -> str:
        """Return the designated protocol of the scenario.

        If the node's mode is :attr:`NodeMode.MANAGED`, we always choose `http` and
        display a warning if there was a 'protocol' set explicitly in the
        scenario's yaml.

        Otherwise we simply access the 'protocol' key of the yaml, defaulting to
        'http' if it does not exist.
        """
        if self.nodes.mode is NodeMode.MANAGED:
            if 'protocol' in self._config:
                log.warning('The "protocol" setting is not supported in "managed" node mode.')
            return 'http'
        return self._config.get('protocol', 'http')

    @property
    def timeout(self) -> int:
        """Returns the scenario's set timeout in seconds."""
        return self.settings.get('timeout', TIMEOUT)

    @property
    def notification_email(self) -> Union[str, None]:
        """Return the email address to which notifications are to be sent.

        If this isn't set, we return None.
        """
        return self.settings.get('notify')

    @property
    def chain_name(self) -> str:
        """Return the name of the chain to be used for this scenario."""
        return self.settings.get('chain', 'any')

    @property
    def services(self):
        """ Return the """
        return self.settings.get('services', {})

    @property
    def gas_price(self) -> str:
        """Return the configured gas price for this scenario.

        This defaults to 'fast'.
        """
        return self._config.get('gas_price', 'fast')

    @property
    def gas_price_strategy(self) -> Callable:
        return get_gas_price_strategy(self.gas_price)

    @property
    def nodes(self) -> NodesConfig:
        """Return the configuration of nodes used in this scenario."""
        return self._nodes

    @property
    def configuration(self):
        """Return the scenario's configuration.

        :raises ScenarioError: if no 'scenario' key is present in the yaml file.
        """
        try:
            return self._config['scenario']
        except KeyError:
            raise ScenarioError(
                "Invalid scenario definition. Missing 'scenario' key.",
            )

    @property
    def task(self) -> Tuple[str, Any]:
        """Return the scenario's task configuration as a tuple.

        :raises MultipleTaskDefinitions:
            if there is more than one task config under the 'scenario' key.
        """
        try:
            items, = self.configuration.items()
        except ValueError:
            raise MultipleTaskDefinitions(
                'Multiple tasks defined in scenario configuration!',
            )
        return items

    @property
    def task_config(self) -> Dict:
        """Return the task config for this scenario."""
        _, root_task_config = self.task
        return root_task_config

    @property
    def task_class(self):
        """Return the Task class type configured for the scenario."""
        from scenario_player.tasks.base import get_task_class_for_type

        root_task_type, _ = self.task

        task_class = get_task_class_for_type(root_task_type)
        return task_class
