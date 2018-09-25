from scenario_player.exceptions import ScenarioAssertionError

from .raiden_api import RaidenAPIActionTask


class OpenChannelTask(RaidenAPIActionTask):
    _name = 'open_channel'
    _url_template = '{protocol}://{target_host}/api/1/channels'
    _method = 'put'

    @property
    def _request_params(self):
        params = dict(
            token_address=self._runner.token_address,
            partner_address=self._runner.node_to_address[
                self._runner.raiden_nodes[
                    self._config['to']
                ]
            ],
        )
        total_deposit = self._config.get('total_deposit')
        if total_deposit:
            params['total_deposit'] = total_deposit
        return params


class ChannelActionTask(RaidenAPIActionTask):
    _url_template = '{protocol}://{target_host}/api/1/channels/{token_address}/{partner_address}'
    _method = 'patch'

    @property
    def _url_params(self):
        return dict(
            token_address=self._runner.token_address,
            partner_address=self._runner.node_to_address[
                self._runner.raiden_nodes[
                    self._config['to']
                ]
            ],
        )


class CloseChannelTask(ChannelActionTask):
    _name = 'close_channel'

    @property
    def _request_params(self):
        return dict(state='closed')


class DepositTask(ChannelActionTask):
    _name = 'deposit'

    @property
    def _request_params(self):
        return dict(total_deposit=self._config['total_deposit'])


class TransferTask(ChannelActionTask):
    _name = 'transfer'
    _url_template = '{protocol}://{target_host}/api/1/payments/{token_address}/{partner_address}'
    _method = 'post'

    @property
    def _request_params(self):
        return dict(amount=self._config['amount'])


class AssertTask(ChannelActionTask):
    _name = 'assert'
    _method = 'get'

    def _process_response(self, response_dict: dict):
        response_dict = super()._process_response(response_dict)
        for field in ['balance', 'total_deposit', 'state']:
            if field not in self._config:
                continue
            if field not in response_dict:
                raise ScenarioAssertionError(
                    f'Field "{field}" is missing in channel: {response_dict}',
                )
            if response_dict[field] != self._config[field]:
                raise ScenarioAssertionError(
                    f'Value mismatch for "{field}". '
                    f'Should: "{self._config[field]}" '
                    f'Is: "{response_dict[field]}" '
                    f'Channel: {response_dict}',
                )
