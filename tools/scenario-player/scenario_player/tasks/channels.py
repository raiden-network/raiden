import hashlib
from typing import Any

import structlog
from toolz import first

from scenario_player.exceptions import ScenarioAssertionError
from scenario_player.runner import ScenarioRunner

from .raiden_api import RaidenAPIActionTask

log = structlog.get_logger(__name__)


class OpenChannelTask(RaidenAPIActionTask):
    _name = 'open_channel'
    _url_template = '{protocol}://{target_host}/api/1/channels'
    _method = 'put'

    @property
    def _request_params(self):
        if isinstance(self._config['to'], str) and len(self._config['to']) == 42:
            partner_address = self._config['to']
        else:
            partner_address = self._runner.get_node_address(self._config['to'])
        params = dict(
            token_address=self._runner.token_address,
            partner_address=partner_address,
        )
        total_deposit = self._config.get('total_deposit')
        if total_deposit is not None:
            params['total_deposit'] = total_deposit
        settle_timeout = self._config.get('settle_timeout')
        if settle_timeout is not None:
            params['settle_timeout'] = settle_timeout
        return params


class ChannelActionTask(RaidenAPIActionTask):
    _url_template = '{protocol}://{target_host}/api/1/channels/{token_address}/{partner_address}'
    _method = 'patch'

    @property
    def _url_params(self):
        if isinstance(self._config['to'], str) and len(self._config['to']) == 42:
            partner_address = self._config['to']
        else:
            partner_address = self._runner.get_node_address(self._config['to'])

        return dict(
            token_address=self._runner.token_address,
            partner_address=partner_address,
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
    _transfer_count = 0

    def __init__(
        self,
        runner: ScenarioRunner,
        config: Any,
        parent: 'Task' = None,
        abort_on_fail=True,
    ) -> None:
        super().__init__(runner, config, parent, abort_on_fail)
        # Unique transfer identifier
        self.__class__._transfer_count += 1
        if str(self._config.get('identifier', '')).lower() == 'generate':
            transfer_count = self.__class__._transfer_count
            scenario_hash = int.from_bytes(
                hashlib.sha256(self._runner.scenario_name.encode()).digest()[:2],
                'little',
            )
            self._config['identifier'] = int(
                f'1{scenario_hash}1{self._runner.run_number:04d}{transfer_count:06d}',
            )

    @property
    def _request_params(self):
        params = dict(
            amount=self._config['amount'],
        )
        if 'identifier' in self._config:
            params['identifier'] = self._config['identifier']
        return params


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


class AssertAllTask(ChannelActionTask):
    _name = 'assert_all'
    _url_template = '{protocol}://{target_host}/api/1/channels/{token_address}'
    _method = 'get'

    @property
    def _url_params(self):
        return dict(token_address=self._runner.token_address)

    def _process_response(self, response_dict: dict):
        response_dict = super()._process_response(response_dict)
        channel_count = len(response_dict)
        for field in ['balance', 'total_deposit', 'state']:
            # The task parameter field names are the plural of the channel field names
            assert_field = f'{field}s'
            if assert_field not in self._config:
                continue
            try:
                channel_field_values = [channel[field] for channel in response_dict]
            except KeyError:
                raise ScenarioAssertionError(
                    f'Field "{field}" is missing in at least one channel: {response_dict}',
                )
            assert_field_value_count = len(self._config[assert_field])
            if assert_field_value_count != channel_count:
                direction = ['many', 'few'][assert_field_value_count < channel_count]
                raise ScenarioAssertionError(
                    f'Assertion field "{field}" has too {direction} values. '
                    f'Have {channel_count} channels but {assert_field_value_count} values.',
                )
            channel_field_values_all = channel_field_values[:]
            for value in self._config[assert_field]:
                try:
                    channel_field_values.remove(value)
                except ValueError:
                    channel_field_values_str = ", ".join(
                        str(val) for val in channel_field_values_all
                    )
                    assert_field_values_str = ', '.join(
                        str(val) for val in self._config[assert_field]
                    )
                    raise ScenarioAssertionError(
                        f'Expected value "{value}" for field "{field}" not found in any channel. '
                        f'Existing values: {channel_field_values_str} '
                        f'Expected values: {assert_field_values_str} '
                        f'Channels: {response_dict}',
                    ) from None
            if len(channel_field_values) != 0:
                raise ScenarioAssertionError(
                    f'Value mismatch for field "{field}". '
                    f'Not all values consumed, remaining: {channel_field_values}',
                )


class AssertSumTask(AssertAllTask):
    _name = 'assert_sum'

    def _process_response(self, response_dict: dict):
        for field in ['balance', 'total_deposit', 'state']:
            # The task parameter field names are the channel field names with a `_sum` suffix
            assert_field = f'{field}_sum'
            if assert_field not in self._config:
                continue
            assert_value = self._config[assert_field]
            if field == 'state':
                # Special case state since it's a string field
                channel_states = {channel['state'] for channel in response_dict}
                if len(channel_states) > 1:
                    raise ScenarioAssertionError(
                        f'Expected all channels to be in "{assert_value}" state. '
                        f'Found: {channel_states}',
                    )
                channel_value_sum = first(channel_states)
            else:
                channel_value_sum = sum(channel[field] for channel in response_dict)
            if assert_value != channel_value_sum:
                raise ScenarioAssertionError(
                    f'Expected sum value "{assert_value}" for channel fields "{field}". '
                    f'Actual value: "{channel_value_sum}". '
                    f'Channels: {response_dict}',
                )
