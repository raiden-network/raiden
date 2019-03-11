import structlog

from scenario_player.exceptions import TransferFailed
from scenario_player.tasks.api_base import RESTAPIActionTask

log = structlog.get_logger(__name__)


class RaidenAPIActionTask(RESTAPIActionTask):
    def _handle_timeout(self, ex: Exception):
        raise TransferFailed(
            f"Transfer didn't complete within timeout of {self._timeout}",
        ) from ex

    @property
    def _target_host(self):
        return self._runner.get_node_baseurl(self._config['from'])

    def _expand_url(self):
        url = self._url_template.format(
            protocol=self._runner.protocol,
            target_host=self._target_host,
            **self._url_params,
        )
        return url
