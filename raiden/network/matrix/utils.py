import json

import gevent
from requests.adapters import HTTPAdapter


def _geventify_callback(callback):
    def inner(*args, **kwargs):
        gevent.spawn(callback, *args, **kwargs)

    return inner


class Fix429HTTPAdapter(HTTPAdapter):
    """ Temporary workaround for https://github.com/matrix-org/matrix-python-sdk/issues/193 """

    _fallback_retry_timeout = 1000

    def build_response(self, req, resp):
        response = super().build_response(req, resp)
        if response.status_code == 429:
            resp_json = response.json()
            if 'retry_after_ms' not in resp_json:
                if 'error' in resp_json:
                    try:
                        error = json.loads(resp_json['error'])
                        resp_json['retry_after_ms'] = error.get('retry_after_ms',
                                                                self._fallback_retry_timeout)
                    except json.JSONDecodeError:
                        resp_json['retry_after_ms'] = self._fallback_retry_timeout
                else:
                    resp_json['retry_after_ms'] = self._fallback_retry_timeout

                response._content = json.dumps(resp_json).encode(
                    response.encoding or response.apparent_encoding)
                print("Fixing response json to ", response._content)
        return response
