import errno
import os
import re
import string
import sys
from ipaddress import AddressValueError, IPv4Address
from itertools import groupby
from pathlib import Path
from string import Template
from typing import Any, Callable, Dict, List, Tuple, Union

import click
import requests
from click import BadParameter
from click._compat import term_len
from click.formatting import iter_rows, measure_table, wrap_text
from pytoml import TomlError, load
from web3.gas_strategies.time_based import fast_gas_price_strategy, medium_gas_price_strategy

from raiden.constants import Environment
from raiden.exceptions import InvalidAddress
from raiden.utils import address_checksum_and_decode
from raiden_contracts.constants import NETWORKNAME_TO_ID

LOG_CONFIG_OPTION_NAME = 'log_config'


class HelpFormatter(click.HelpFormatter):
    """
    Subclass that allows multiple (option) sections to be formatted with pre-determined
    widths.
    """

    def write_dl(self, rows, col_max=30, col_spacing=2, widths=None):
        """Writes a definition list into the buffer.  This is how options
        and commands are usually formatted.

        :param rows: a list of two item tuples for the terms and values.
        :param col_max: the maximum width of the first column.
        :param col_spacing: the number of spaces between the first and
                            second column.
        :param widths: optional pre-calculated line widths
        """
        rows = list(rows)
        if widths is None:
            widths = measure_table(rows)
        if len(widths) != 2:
            raise TypeError('Expected two columns for definition list')

        first_col = min(widths[0], col_max) + col_spacing

        for first, second in iter_rows(rows, len(widths)):
            self.write('%*s%s' % (self.current_indent, '', first))
            if not second:
                self.write('\n')
                continue
            if term_len(first) <= first_col - col_spacing:
                self.write(' ' * (first_col - term_len(first)))
            else:
                self.write('\n')
                self.write(' ' * (first_col + self.current_indent))

            text_width = max(self.width - first_col - 2, 10)
            lines = iter(wrap_text(second, text_width).splitlines())
            if lines:
                self.write(next(lines) + '\n')
                for line in lines:
                    self.write('%*s%s\n' % (
                        first_col + self.current_indent, '', line))
            else:
                self.write('\n')


class Context(click.Context):
    def make_formatter(self):
        return HelpFormatter(width=self.terminal_width, max_width=self.max_content_width)


class CustomContextMixin:
    """ Use above context class instead of the click default """

    def make_context(self, info_name, args, parent=None, **extra):
        """
        This function when given an info name and arguments will kick
        off the parsing and create a new :class:`Context`.  It does not
        invoke the actual command callback though.

        :param info_name: the info name for this invokation.  Generally this
                          is the most descriptive name for the script or
                          command.  For the toplevel script it's usually
                          the name of the script, for commands below it it's
                          the name of the script.
        :param args: the arguments to parse as list of strings.
        :param parent: the parent context if available.
        :param extra: extra keyword arguments forwarded to the context
                      constructor.
        """
        for key, value in iter(self.context_settings.items()):
            if key not in extra:
                extra[key] = value
        ctx = Context(self, info_name=info_name, parent=parent, **extra)
        with ctx.scope(cleanup=False):
            self.parse_args(ctx, args)
        return ctx


class GroupableOption(click.Option):
    def __init__(
            self,
            param_decls=None,
            show_default=False,
            prompt=False,
            confirmation_prompt=False,
            hide_input=False,
            is_flag=None,
            flag_value=None,
            multiple=False,
            count=False,
            allow_from_autoenv=True,
            option_group=None,
            **attrs,
    ):
        super().__init__(
            param_decls,
            show_default,
            prompt,
            confirmation_prompt,
            hide_input,
            is_flag,
            flag_value,
            multiple,
            count,
            allow_from_autoenv,
            **attrs,
        )
        self.option_group = option_group


class GroupableOptionCommand(CustomContextMixin, click.Command):
    def format_options(self, ctx, formatter):
        def keyfunc(o):
            value = getattr(o, 'option_group', None)
            return value if value is not None else ''

        grouped_options = groupby(
            sorted(
                self.get_params(ctx),
                key=keyfunc,
            ),
            key=keyfunc,
        )

        options = {}
        for option_group, params in grouped_options:
            for param in params:
                rv = param.get_help_record(ctx)
                if rv is not None:
                    options.setdefault(option_group, []).append(rv)

        if options:
            widths_a, widths_b = list(
                zip(*[measure_table(group_options) for group_options in options.values()]),
            )
            widths = (max(widths_a), max(widths_b))

            for option_group, group_options in options.items():
                with formatter.section(option_group if option_group else 'Options'):
                    formatter.write_dl(group_options, widths=widths)


class GroupableOptionCommandGroup(CustomContextMixin, click.Group):
    def format_options(self, ctx, formatter):
        GroupableOptionCommand.format_options(self, ctx, formatter)
        self.format_commands(ctx, formatter)

    def command(self, *args, **kwargs):
        return super().command(*args, **{'cls': GroupableOptionCommand, **kwargs})

    def group(self, *args, **kwargs):
        return super().group(*args, **{'cls': self.__class__, **kwargs})


def command(name=None, cls=GroupableOptionCommand, **attrs):
    return click.command(name, cls, **attrs)


def group(name=None, **attrs):
    return click.group(name, **{'cls': GroupableOptionCommandGroup, **attrs})


def option(*args, **kwargs):
    return click.option(*args, **{'cls': GroupableOption, **kwargs})


def option_group(name: str, *options: List[Callable]):
    def decorator(f):
        for option_ in reversed(options):
            for closure_cell in option_.__closure__:
                if isinstance(closure_cell.cell_contents, dict):
                    closure_cell.cell_contents['option_group'] = name
                    break
            option_(f)
        return f

    return decorator


class AddressType(click.ParamType):
    name = 'address'

    def convert(self, value, param, ctx):
        try:
            return address_checksum_and_decode(value)
        except InvalidAddress as e:
            self.fail(str(e))


class LogLevelConfigType(click.ParamType):
    name = 'log-config'
    _validate_re = re.compile(
        r'^(?:'
        r'(?P<logger_name>[a-zA-Z0-9._]+)?'
        r':'
        r'(?P<logger_level>debug|info|warn(?:ing)?|error|critical|fatal)'
        r',?)*$',
        re.IGNORECASE,
    )

    def convert(self, value, param, ctx):
        if not self._validate_re.match(value):
            self.fail('Invalid log config format')
        level_config = dict()
        if value.strip(' ') == '':
            return None  # default value

        for logger_config in value.split(','):
            logger_name, logger_level = logger_config.split(':')
            level_config[logger_name] = logger_level.upper()
        return level_config


class NATChoiceType(click.Choice):
    def convert(self, value, param, ctx):
        if value.startswith('ext:'):
            ip, _, port = value[4:].partition(':')
            try:
                IPv4Address(ip)
            except AddressValueError:
                self.fail('invalid IP address: {}'.format(ip), param, ctx)
            if port:
                try:
                    port = int(port, 0)
                except ValueError:
                    self.fail('invalid port number: {}'.format(port), param, ctx)
            else:
                port = None
            return ip, port
        return super().convert(value, param, ctx)


class NetworkChoiceType(click.Choice):
    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        elif isinstance(value, str) and value.isnumeric():
            try:
                return int(value)
            except ValueError:
                self.fail(f'invalid numeric network id: {value}', param, ctx)
        else:
            network_name = super().convert(value, param, ctx)
            return NETWORKNAME_TO_ID[network_name]


class EnvironmentChoiceType(click.Choice):
    def convert(self, value, param, ctx):
        try:
            return Environment(value)
        except ValueError:
            self.fail(f"'{value}' is not a valid environment type", param, ctx)


class GasPriceChoiceType(click.Choice):
    """ Returns a GasPriceStrategy for the choice """

    def convert(self, value, param, ctx):
        if isinstance(value, str) and value.isnumeric():
            try:
                gas_price = int(value)

                def fixed_gas_price_strategy(_web3, _transaction_params):
                    return gas_price

                return fixed_gas_price_strategy
            except ValueError:
                self.fail(f'invalid numeric gas price: {value}', param, ctx)
        else:
            gas_price_string = super().convert(value, param, ctx)
            if gas_price_string == 'fast':
                return fast_gas_price_strategy
            else:
                return medium_gas_price_strategy


class MatrixServerType(click.Choice):
    def convert(self, value, param, ctx):
        if value.startswith('http'):
            return value
        return super().convert(value, param, ctx)


class HypenTemplate(Template):
    idpattern = r'(?-i:[_a-zA-Z-][_a-zA-Z0-9-]*)'


class PathRelativePath(click.Path):
    """
    `click.Path` subclass that can default to a value depending on
    another option of type `click.Path`.

    Uses :ref:`string.Template` to expand the parameters default value.

    Example::

        @click.option('--some-dir', type=click.Path())
        @click.option('--some-file', type=PathRelativePath(), default='${some-dir}/file.txt')
    """

    def convert(self, value, param, ctx):
        if value == param.default:
            try:
                value = self.expand_default(value, ctx.params)
            except KeyError as ex:
                raise RuntimeError(
                    'Subsitution parameter not found in context. '
                    'Make sure it\'s defined with `is_eager=True`.'  # noqa: C812
                ) from ex

        return super().convert(value, param, ctx)

    @staticmethod
    def expand_default(default, params):
        return HypenTemplate(default).substitute(params)


def apply_config_file(
        command_function: Union[click.Command, click.Group],
        cli_params: Dict[str, Any],
        ctx,
        config_file_option_name='config_file',
):
    """ Applies all options set in the config file to `cli_params` """
    paramname_to_param = {param.name: param for param in command_function.params}
    path_params = {
        param.name
        for param in command_function.params
        if isinstance(param.type, (click.Path, click.File))
    }

    config_file_path = Path(cli_params[config_file_option_name])
    config_file_values = dict()
    try:
        with config_file_path.open() as config_file:
            config_file_values = load(config_file)
    except OSError as ex:
        # Silently ignore if 'file not found' and the config file path is the default
        config_file_param = paramname_to_param[config_file_option_name]
        config_file_default_path = Path(
            config_file_param.type.expand_default(config_file_param.get_default(ctx), cli_params),
        )
        default_config_missing = (
            ex.errno == errno.ENOENT and
            config_file_path.resolve() == config_file_default_path.resolve()
        )
        if default_config_missing:
            cli_params['config_file'] = None
        else:
            click.secho(f"Error opening config file: {ex}", fg='red')
            sys.exit(1)
    except TomlError as ex:
        click.secho(f'Error loading config file: {ex}', fg='red')
        sys.exit(1)

    for config_name, config_value in config_file_values.items():
        config_name_int = config_name.replace('-', '_')

        if config_name_int not in paramname_to_param:
            click.secho(
                f"Unknown setting '{config_name}' found in config file - ignoring.",
                fg='yellow',
            )
            continue

        if config_name_int in path_params:
            # Allow users to use `~` in paths in the config file
            config_value = os.path.expanduser(config_value)

        if config_name_int == LOG_CONFIG_OPTION_NAME:
            # Uppercase log level names
            config_value = {k: v.upper() for k, v in config_value.items()}
        else:
            # Pipe config file values through cli converter to ensure correct types
            # We exclude `log-config` because it already is a dict when loading from toml
            try:
                config_value = paramname_to_param[config_name_int].type.convert(
                    config_value,
                    paramname_to_param[config_name_int],
                    ctx,
                )
            except click.BadParameter as ex:
                click.secho(f"Invalid config file setting '{config_name}': {ex}", fg='red')
                sys.exit(1)

        # Use the config file value if the value from the command line is the default
        if cli_params[config_name_int] == paramname_to_param[config_name_int].get_default(ctx):
            cli_params[config_name_int] = config_value


def get_matrix_servers(url: str) -> List[str]:
    """Fetch a list of matrix servers from a text url

    '-' prefixes (YAML list) are cleaned. Comment lines /^\\s*#/ are ignored

    url: url of a text file
    returns: list of urls, default schema is https
    """
    try:
        response = requests.get(url)
        if response.status_code != 200:
            raise requests.RequestException('Response: {response!r}')
    except requests.RequestException as ex:
        raise RuntimeError(f'Could not fetch matrix servers list: {url!r} => {ex!r}') from ex

    available_servers = []
    for line in response.text.splitlines():
        line = line.strip(string.whitespace + '-')
        if line.startswith('#') or not line:
            continue
        if not line.startswith('http'):
            line = 'https://' + line  # default schema
        available_servers.append(line)
    return available_servers


def validate_option_dependencies(
        command_function: Union[click.Command, click.Group],
        ctx,
        cli_params: Dict[str, Any],
        option_dependencies: Dict[str, List[Tuple[str, Any]]],
):
    paramname_to_param = {param.name: param for param in command_function.params}

    for depending_option_name, requirements in option_dependencies.items():
        depending_option_name_int = depending_option_name.replace('-', '_')
        param = paramname_to_param[depending_option_name_int]

        depending_option_value = cli_params[depending_option_name_int]
        if depending_option_value is None:
            continue

        depending_option_value_default = param.get_default(ctx)
        if depending_option_value == depending_option_value_default:
            # Ignore dependencies for default values
            continue

        for depended_option_name, depended_option_required_value in requirements:
            depended_option_name_int = depended_option_name.replace('-', '_')
            depended_option_actual_value = cli_params[depended_option_name_int]
            if depended_option_actual_value != depended_option_required_value:
                raise BadParameter(
                    f'This option is only available when option "--{depended_option_name}" '
                    f'is set to "{depended_option_required_value}". '
                    f'Current value: "{depended_option_actual_value}"',
                    ctx,
                    param,
                )


ADDRESS_TYPE = AddressType()
LOG_LEVEL_CONFIG_TYPE = LogLevelConfigType()
