from requests import RequestException

from scenario_player.exceptions import RESTAPIError

from .base import Task


class RaidenAPIActionTask(Task):
    _name = ''
    _url_template = ""
    _method = 'get'

    @property
    def _request_params(self):
        return {}

    @property
    def _url_params(self):
        return {}

    @property
    def _target_host(self):
        return self._runner.raiden_nodes[self._config['from']]

    def _process_response(self, response: dict):
        return response

    def _run(self, *args, **kwargs):
        url = self._url_template.format(
            protocol=self._runner.protocol,
            target_host=self._target_host,
            **self._url_params,
        )
        try:
            resp = self._runner.session.request(self._method, url, json=self._request_params)
        except RequestException as ex:
            raise RESTAPIError(f'Error performing REST-API call: {self._name}') from ex
        if not 199 < resp.status_code < 300:
            raise RESTAPIError(f'Status {resp.status_code} while fetching {url}: {resp.text}')
        try:
            return self._process_response(resp.json())
        except (ValueError, UnicodeDecodeError) as ex:
            raise RESTAPIError(
                f'Error decoding response for url {url}: {resp.status_code} {resp.text}',
            ) from ex
