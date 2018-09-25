from .raiden_api import RaidenAPIActionTask


class LeaveTokenNetwork(RaidenAPIActionTask):
    _name = 'leave_network'
    _url_template = '{protocol}://{target_host}/api/1/connections/{token_address}'
    _method = 'delete'

    @property
    def _url_params(self):
        params = dict(
            token_address=self._runner.token_address,
        )
        return params
