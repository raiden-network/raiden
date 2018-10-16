import re
from typing import Any, Union

import structlog
from requests import RequestException

from scenario_player.exceptions import RESTAPIError, RESTAPIStatusMismatchError
from scenario_player.runner import ScenarioRunner

from .base import Task

log = structlog.get_logger(__name__)


class RaidenAPIActionTask(Task):
    _name = ''
    _url_template = ""
    _method = 'get'
    _expected_http_status: Union[int, str] = '2..'

    def __init__(
        self,
        runner: ScenarioRunner,
        config: Any,
        parent: 'Task' = None,
        abort_on_fail=True,
    ) -> None:
        super().__init__(runner, config, parent, abort_on_fail)

        self._expected_http_status = config.get('expected_http_status', self._expected_http_status)
        self._http_status_re = re.compile(f'^{self._expected_http_status}$')

    @property
    def _request_params(self):
        return {}

    @property
    def _url_params(self):
        return {}

    @property
    def _target_host(self):
        return self._runner.get_node_baseurl(self._config['from'])

    def _process_response(self, response_dict: dict):
        return response_dict

    def _run(self, *args, **kwargs):
        url = self._url_template.format(
            protocol=self._runner.protocol,
            target_host=self._target_host,
            **self._url_params,
        )
        log.debug('Requesting', url=url, method=self._method)
        try:
            resp = self._runner.session.request(self._method, url, json=self._request_params)
        except RequestException as ex:
            raise RESTAPIError(f'Error performing REST-API call: {self._name}') from ex
        if not self._http_status_re.match(str(resp.status_code)):
            raise RESTAPIStatusMismatchError(
                f'HTTP status code "{resp.status_code}" while fetching {url}. '
                f'Expected {self._expected_http_status}: {resp.text}',
            )
        try:
            if resp.content == b'':
                # Allow empty responses
                response_dict = {}
            else:
                response_dict = resp.json()
            return self._process_response(response_dict)
        except (ValueError, UnicodeDecodeError) as ex:
            raise RESTAPIError(
                f'Error decoding response for url {url}: {resp.status_code} {resp.text}',
            ) from ex
