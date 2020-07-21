import errno
import os
import re
import string
from enum import EnumMeta
from itertools import groupby
from pathlib import Path
from string import Template
from typing import Any, Callable, Dict, List, MutableMapping, Union

import click
import requests
from click import Choice, MissingParameter
from click._compat import term_len
from click.formatting import iter_rows, measure_table, wrap_text
from eth_typing import URI
from toml import TomlDecodeError, load
from web3.gas_strategies.time_based import fast_gas_price_strategy

from raiden.exceptions import ConfigurationError, InvalidChecksummedAddress
from raiden.network.rpc.middleware import faster_gas_price_strategy
from raiden.utils.formatting import address_checksum_and_decode
from raiden_contracts.constants import CHAINNAME_TO_ID

CONTEXT_KEY_DEFAULT_OPTIONS = "raiden.options_using_default"
LOG_CONFIG_OPTION_NAME = "log_config"


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
            raise TypeError("Expected two columns for definition list")

        first_col = min(widths[0], col_max) + col_spacing

        for first, second in iter_rows(rows, len(widths)):
            self.write("%*s%s" % (self.current_indent, "", first))
            if not second:
                self.write("\n")
                continue
            if term_len(first) <= first_col - col_spacing:
                self.write(" " * (first_col - term_len(first)))
            else:
                self.write("\n")
                self.write(" " * (first_col + self.current_indent))

            text_width = max(self.width - first_col - 2, 10)
            lines = iter(wrap_text(second, text_width).splitlines())
            if lines:
                self.write(next(lines) + "\n")
                for line in lines:
                    self.write("%*s%s\n" % (first_col + self.current_indent, "", line))
            else:
                self.write("\n")


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
        for key, value in iter(self.context_settings.items()):  # type: ignore
            if key not in extra:
                extra[key] = value
        ctx = Context(self, info_name=info_name, parent=parent, **extra)  # type: ignore
        with ctx.scope(cleanup=False):
            self.parse_args(ctx, args)  # type: ignore
        return ctx


class UsesDefaultValueOptionMixin(click.Option):
    def full_process_value(self, ctx, value):
        """
        Slightly modified copy of ``Option.full_process_value()`` that records which options use
        default values in ``ctx.meta['raiden.options_using_default']``.

        This is then used in ``apply_config_file()`` to establish precedence between values given
        via the config file and the cli.
        """
        if value is None and self.prompt is not None and not ctx.resilient_parsing:  # type: ignore
            return self.prompt_for_value(ctx)

        value = self.process_value(ctx, value)

        if value is None:
            value = self.get_default(ctx)
            if not self.value_is_missing(value):
                ctx.meta.setdefault(CONTEXT_KEY_DEFAULT_OPTIONS, set()).add(self.name)

        if self.required and self.value_is_missing(value):
            raise MissingParameter(ctx=ctx, param=self)

        return value


class GroupableOption(UsesDefaultValueOptionMixin, click.Option):
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
            value = getattr(o, "option_group", None)
            return value if value is not None else ""

        grouped_options = groupby(sorted(self.get_params(ctx), key=keyfunc), key=keyfunc)

        options: Dict = {}
        for option_group, params in grouped_options:
            for param in params:
                rv = param.get_help_record(ctx)
                if rv is not None:
                    options.setdefault(option_group, []).append(rv)

        if options:
            widths_a, widths_b = list(
                zip(*[measure_table(group_options) for group_options in options.values()])
            )
            widths = (max(widths_a), max(widths_b))

            for option_group, group_options in options.items():
                with formatter.section(option_group if option_group else "Options"):
                    formatter.write_dl(group_options, widths=widths)


class GroupableOptionCommandGroup(CustomContextMixin, click.Group):
    def format_options(self, ctx, formatter):
        GroupableOptionCommand.format_options(self, ctx, formatter)  # type: ignore
        self.format_commands(ctx, formatter)

    def command(self, *args, **kwargs):
        return super().command(*args, **{"cls": GroupableOptionCommand, **kwargs})

    def group(self, *args, **kwargs):
        return super().group(*args, **{"cls": self.__class__, **kwargs})


def command(name=None, cls=GroupableOptionCommand, **attrs):
    return click.command(name, cls, **attrs)


def group(name=None, **attrs):
    return click.group(name, **{"cls": GroupableOptionCommandGroup, **attrs})  # type: ignore


def option(*args, **kwargs):
    return click.option(*args, **{"cls": GroupableOption, **kwargs})  # type: ignore


def option_group(name: str, *options: Callable):
    def decorator(f):
        for option_ in reversed(options):
            for closure_cell in option_.__closure__:  # type: ignore
                if isinstance(closure_cell.cell_contents, dict):
                    closure_cell.cell_contents["option_group"] = name
                    break
            option_(f)
        return f

    return decorator


class AddressType(click.ParamType):
    name = "address"

    def convert(self, value, param, ctx):  # pylint: disable=unused-argument
        try:
            return address_checksum_and_decode(value)
        except InvalidChecksummedAddress as e:
            self.fail(str(e))


class LogLevelConfigType(click.ParamType):
    name = "log-config"
    _validate_re = re.compile(
        r"^(?:"
        r"(?P<logger_name>[a-zA-Z0-9._]+)?"
        r":"
        r"(?P<logger_level>debug|info|warn(?:ing)?|error|critical|fatal)"
        r",?)*$",
        re.IGNORECASE,
    )

    def convert(self, value, param, ctx):  # pylint: disable=unused-argument
        if not self._validate_re.match(value):
            self.fail("Invalid log config format")
        level_config = dict()
        if value.strip(" ") == "":
            return None  # default value

        for logger_config in value.split(","):
            logger_name, logger_level = logger_config.split(":")
            level_config[logger_name] = logger_level.upper()
        return level_config


class NetworkChoiceType(click.Choice):
    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        elif isinstance(value, str) and value.isnumeric():
            try:
                return int(value)
            except ValueError:
                self.fail(f"invalid numeric network id: {value}", param, ctx)
        else:
            network_name = super().convert(value, param, ctx)
            return CHAINNAME_TO_ID[network_name]


class EnumChoiceType(Choice):
    def __init__(self, enum_type: EnumMeta, case_sensitive=True):
        self._enum_type = enum_type
        # https://github.com/python/typeshed/issues/2942
        super().__init__(
            [choice.value for choice in enum_type], case_sensitive=case_sensitive  # type: ignore
        )

    def convert(self, value, param, ctx):
        try:
            return self._enum_type(value)
        except ValueError:
            self.fail(f"'{value}' is not a valid {self._enum_type.__name__.lower()}", param, ctx)


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
                self.fail(f"invalid numeric gas price: {value}", param, ctx)
        else:
            gas_price_string = super().convert(value, param, ctx)
            if gas_price_string == "fast":
                return faster_gas_price_strategy
            else:
                return fast_gas_price_strategy


class MatrixServerType(click.Choice):
    def convert(self, value, param, ctx):
        if value.startswith("http"):
            return value
        return super().convert(value, param, ctx)


class HypenTemplate(Template):
    idpattern = r"(?-i:[_a-zA-Z-][_a-zA-Z0-9-]*)"


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
                    "Subsitution parameter not found in context. "
                    "Make sure it's defined with `is_eager=True`."  # noqa: C812
                ) from ex

        return super().convert(value, param, ctx)

    @staticmethod
    def expand_default(default, params):
        return HypenTemplate(default).substitute(params)


def apply_config_file(
    command_function: Union[click.Command, click.Group],
    cli_params: Dict[str, Any],
    ctx,
    config_file_option_name="config_file",
):
    """ Applies all options set in the config file to `cli_params` """
    options_using_default = ctx.meta.get(CONTEXT_KEY_DEFAULT_OPTIONS, set())
    paramname_to_param = {param.name: param for param in command_function.params}
    path_params = {
        param.name
        for param in command_function.params
        if isinstance(param.type, (click.Path, click.File))
    }

    config_file_path = Path(cli_params[config_file_option_name])
    config_file_values: MutableMapping[str, Any] = dict()
    try:
        with config_file_path.open() as config_file:
            config_file_values = load(config_file)
    except OSError as ex:
        # Silently ignore if 'file not found' and the config file path is the default and
        # the option wasn't explicitly supplied on the command line
        config_file_param = paramname_to_param[config_file_option_name]
        config_file_default_path = Path(
            config_file_param.type.expand_default(  # type: ignore
                config_file_param.get_default(ctx), cli_params
            )
        )
        default_config_missing = (
            ex.errno == errno.ENOENT
            and config_file_path.resolve() == config_file_default_path.resolve()
            and config_file_option_name in options_using_default
        )
        if default_config_missing:
            cli_params["config_file"] = None
        else:
            raise ConfigurationError(f"Error opening config file: {ex}")

    except TomlDecodeError as ex:
        raise ConfigurationError(f"Error loading config file: {ex}")

    for config_name, config_value in config_file_values.items():
        config_name_int = config_name.replace("-", "_")

        if config_name_int not in paramname_to_param:
            click.secho(
                f"Unknown setting '{config_name}' found in config file - ignoring.", fg="yellow"
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
                    config_value, paramname_to_param[config_name_int], ctx
                )
            except click.BadParameter as ex:
                raise ConfigurationError(f"Invalid config file setting '{config_name}': {ex}")

        # Only use the config file value if the option wasn't explicitly given on the command line
        option_has_default = paramname_to_param[config_name_int].default is not None
        if not option_has_default or config_name_int in options_using_default:
            cli_params[config_name_int] = config_value


def get_matrix_servers(url: str) -> List[URI]:
    """Fetch a list of matrix servers from a text url

    '-' prefixes (YAML list) are cleaned. Comment lines /^\\s*#/ are ignored

    url: url of a text file
    returns: list of urls, default schema is https
    """
    try:
        response = requests.get(url)
        if response.status_code != 200:
            raise requests.RequestException("Response: {response!r}")
    except requests.RequestException as ex:
        raise RuntimeError(f"Could not fetch matrix servers list: {url!r} => {ex!r}") from ex

    available_servers = []
    for line in response.text.splitlines():
        line = line.strip(string.whitespace + "-")
        if line.startswith("#") or not line:
            continue
        if not line.startswith("http"):
            line = "https://" + line  # default schema
        available_servers.append(URI(line))
    return available_servers


ADDRESS_TYPE = AddressType()
LOG_LEVEL_CONFIG_TYPE = LogLevelConfigType()
