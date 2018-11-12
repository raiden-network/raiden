from .raiden_api import RaidenAPIActionTask


class JoinTokenNetwork(RaidenAPIActionTask):
    _name = 'join_network'
    _url_template = '{protocol}://{target_host}/api/1/connections/{token_address}'
    _method = 'put'

    @property
    def _url_params(self):
        params = dict(
            token_address=self._runner.token_address,
        )
        return params

    @property
    def _request_params(self):
        params = dict(
            funds=self._config.get('funds'),
        )

        initial_channel_target = self._config.get('initial_channel_target')
        if initial_channel_target is not None:
            params['initial_channel_target'] = initial_channel_target
        joinable_funds_target = self._config.get('joinable_funds_target')
        if joinable_funds_target is not None:
            params['joinable_funds_target'] = joinable_funds_target

        return params


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
