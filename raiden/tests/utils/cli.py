from typing import Any, Dict, Tuple
from unittest import mock

from click.core import ParameterSource  # type: ignore

from raiden.ui import cli


def get_invoked_kwargs(cli_input, cli_runner, capture_function):

    cli_args = cli_input.split()
    command = cli_args[0]
    assert command == "raiden"
    call_args = cli_args[1:] or None

    with mock.patch(capture_function, autospec=True) as mock_run:
        result = cli_runner.invoke(cli.run, call_args)
        assert result.exit_code == 0
        assert not result.exception
        assert mock_run.called
        args, kwargs = mock_run.call_args

    return args, kwargs


def get_cli_result(cli_input, cli_runner, capture_function):

    cli_args = cli_input.split()
    command = cli_args[0]
    assert command == "raiden"
    call_args = cli_args[1:] or None

    with mock.patch(capture_function, autospec=True):
        result = cli_runner.invoke(cli.run, call_args)
        return result


def assert_invoked_kwargs(
    kwargs: Dict[str, Any], expected_args: Dict[str, Tuple[ParameterSource, Any]]
):
    ctx = kwargs["ctx"]

    dic = {}
    for k, v in kwargs.items():
        if k in expected_args:
            dic[k] = (ctx.get_parameter_source(k), v)

    assert dic == expected_args
