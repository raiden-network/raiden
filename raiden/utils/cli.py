import re
from ipaddress import IPv4Address, AddressValueError
from itertools import groupby
from string import Template
from typing import Callable, List

import click
from click._compat import term_len
from click.formatting import iter_rows, measure_table, wrap_text

from raiden.utils import address_checksum_and_decode
from raiden.constants import NETWORKNAME_TO_ID
from raiden.exceptions import InvalidAddress


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
            type=None,
            help=None,
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
            type,
            help,
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
        if isinstance(value, str) and value.isnumeric():
            try:
                return int(value)
            except ValueError:
                self.fail(f'invalid numeric network id: {value}', param, ctx)
        else:
            network_name = super().convert(value, param, ctx)
            return NETWORKNAME_TO_ID[network_name]


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


ADDRESS_TYPE = AddressType()
LOG_LEVEL_CONFIG_TYPE = LogLevelConfigType()
