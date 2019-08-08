#!/usr/bin/env python

"""
Utility to format Raiden json logs into HTML.
Colorizes log key-values according to their md5 hash to make debugging easier.
Allows to filter records by `event`.
"""

import hashlib
import json
from collections import Counter, namedtuple
from copy import copy
from datetime import datetime
from html import escape
from json import JSONDecodeError
from math import log10
from typing import (
    Any,
    Counter as CounterType,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Set,
    TextIO,
    Tuple,
    Union,
)

import click
from cachetools import LRUCache, cached
from click import UsageError
from click._compat import _default_text_stderr
from colour import Color
from eth_utils import is_address, to_canonical_address

from raiden.utils import pex

Record = namedtuple("Line", ("event", "timestamp", "logger", "level", "fields"))

TIME_PAST = datetime(1970, 1, 1)
TIME_FUTURE = datetime(9999, 1, 1)

COLORMAP = [
    "#440154",
    "#440256",
    "#450457",
    "#450559",
    "#46075a",
    "#46085c",
    "#460a5d",
    "#460b5e",
    "#470d60",
    "#470e61",
    "#471063",
    "#471164",
    "#471365",
    "#481467",
    "#481668",
    "#481769",
    "#48186a",
    "#481a6c",
    "#481b6d",
    "#481c6e",
    "#481d6f",
    "#481f70",
    "#482071",
    "#482173",
    "#482374",
    "#482475",
    "#482576",
    "#482677",
    "#482878",
    "#482979",
    "#472a7a",
    "#472c7a",
    "#472d7b",
    "#472e7c",
    "#472f7d",
    "#46307e",
    "#46327e",
    "#46337f",
    "#463480",
    "#453581",
    "#453781",
    "#453882",
    "#443983",
    "#443a83",
    "#443b84",
    "#433d84",
    "#433e85",
    "#423f85",
    "#424086",
    "#424186",
    "#414287",
    "#414487",
    "#404588",
    "#404688",
    "#3f4788",
    "#3f4889",
    "#3e4989",
    "#3e4a89",
    "#3e4c8a",
    "#3d4d8a",
    "#3d4e8a",
    "#3c4f8a",
    "#3c508b",
    "#3b518b",
    "#3b528b",
    "#3a538b",
    "#3a548c",
    "#39558c",
    "#39568c",
    "#38588c",
    "#38598c",
    "#375a8c",
    "#375b8d",
    "#365c8d",
    "#365d8d",
    "#355e8d",
    "#355f8d",
    "#34608d",
    "#34618d",
    "#33628d",
    "#33638d",
    "#32648e",
    "#32658e",
    "#31668e",
    "#31678e",
    "#31688e",
    "#30698e",
    "#306a8e",
    "#2f6b8e",
    "#2f6c8e",
    "#2e6d8e",
    "#2e6e8e",
    "#2e6f8e",
    "#2d708e",
    "#2d718e",
    "#2c718e",
    "#2c728e",
    "#2c738e",
    "#2b748e",
    "#2b758e",
    "#2a768e",
    "#2a778e",
    "#2a788e",
    "#29798e",
    "#297a8e",
    "#297b8e",
    "#287c8e",
    "#287d8e",
    "#277e8e",
    "#277f8e",
    "#27808e",
    "#26818e",
    "#26828e",
    "#26828e",
    "#25838e",
    "#25848e",
    "#25858e",
    "#24868e",
    "#24878e",
    "#23888e",
    "#23898e",
    "#238a8d",
    "#228b8d",
    "#228c8d",
    "#228d8d",
    "#218e8d",
    "#218f8d",
    "#21908d",
    "#21918c",
    "#20928c",
    "#20928c",
    "#20938c",
    "#1f948c",
    "#1f958b",
    "#1f968b",
    "#1f978b",
    "#1f988b",
    "#1f998a",
    "#1f9a8a",
    "#1e9b8a",
    "#1e9c89",
    "#1e9d89",
    "#1f9e89",
    "#1f9f88",
    "#1fa088",
    "#1fa188",
    "#1fa187",
    "#1fa287",
    "#20a386",
    "#20a486",
    "#21a585",
    "#21a685",
    "#22a785",
    "#22a884",
    "#23a983",
    "#24aa83",
    "#25ab82",
    "#25ac82",
    "#26ad81",
    "#27ad81",
    "#28ae80",
    "#29af7f",
    "#2ab07f",
    "#2cb17e",
    "#2db27d",
    "#2eb37c",
    "#2fb47c",
    "#31b57b",
    "#32b67a",
    "#34b679",
    "#35b779",
    "#37b878",
    "#38b977",
    "#3aba76",
    "#3bbb75",
    "#3dbc74",
    "#3fbc73",
    "#40bd72",
    "#42be71",
    "#44bf70",
    "#46c06f",
    "#48c16e",
    "#4ac16d",
    "#4cc26c",
    "#4ec36b",
    "#50c46a",
    "#52c569",
    "#54c568",
    "#56c667",
    "#58c765",
    "#5ac864",
    "#5cc863",
    "#5ec962",
    "#60ca60",
    "#63cb5f",
    "#65cb5e",
    "#67cc5c",
    "#69cd5b",
    "#6ccd5a",
    "#6ece58",
    "#70cf57",
    "#73d056",
    "#75d054",
    "#77d153",
    "#7ad151",
    "#7cd250",
    "#7fd34e",
    "#81d34d",
    "#84d44b",
    "#86d549",
    "#89d548",
    "#8bd646",
    "#8ed645",
    "#90d743",
    "#93d741",
    "#95d840",
    "#98d83e",
    "#9bd93c",
    "#9dd93b",
    "#a0da39",
    "#a2da37",
    "#a5db36",
    "#a8db34",
    "#aadc32",
    "#addc30",
    "#b0dd2f",
    "#b2dd2d",
    "#b5de2b",
    "#b8de29",
    "#bade28",
    "#bddf26",
    "#c0df25",
    "#c2df23",
    "#c5e021",
    "#c8e020",
    "#cae11f",
    "#cde11d",
    "#d0e11c",
    "#d2e21b",
    "#d5e21a",
    "#d8e219",
    "#dae319",
    "#dde318",
    "#dfe318",
    "#e2e418",
    "#e5e419",
    "#e7e419",
    "#eae51a",
    "#ece51b",
    "#efe51c",
    "#f1e51d",
    "#f4e61e",
    "#f6e620",
    "#f8e621",
    "#fbe723",
    "#fde725",
]


PAGE_BEGIN = """\
<!doctype html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<style>
* {{
    font-family: "Fira Code", "Anonymous Pro", "Inconsolata", Menlo, "Source Code Pro",
        "Envy Code R", Hack, "Ubuntu Mono", "Droid Sans Mono", "Deja Vu Sans Mono", "Courier New",
        Courier;
    font-size: small;
}}
body {{
    background: #202020;
    color: white;
}}
table {{
    white-space: nowrap;
    border: none;
}}
table tr.head {{
    position: sticky;
}}
table tr:nth-child(2) {{
    padding-top: 15px;
}}
table tr:nth-child(odd) {{
    background-color: #303030;
}}
table tr:nth-child(even) {{
    background-color: #202020;
}}
table tr td:first-child {{
    background-color: inherit;
    position: sticky;
    position: -webkit-sticky;
    left: 8px;
}}
table td {{
    padding-right: 5px;
    vertical-align: top;
}}
table tr:hover {{
    outline: 1px solid #d02020;
}}
table tr.highlight {{
    outline: 1px solid #20d020;
}}
td.no, td.time * {{
    white-space: pre;
    font-family: courier;
}}
td.no {{
    text-align: right;
}}
.lvl-debug {{
    color: #20d0d0;
}}
.lvl-info {{
    color: #20d020;
}}
.lvl-warning {{
    color: #d0d020;
}}
.lvl-error {{
    color: #d04020;
}}
.fn {{
    color: #f040f0;
}}
</style>
<body>
<h1>{name}</h1>
<h2>Generated on: {date:%Y-%m-%d %H:%M}</h2>
<table>
<tr class="head">
   <td>No</td>
   <td>Event</td>
   <td>Timestamp</td>
   <td>Logger</td>
   <td>Level</td>
   <td>Fields</td>
</tr>
"""

PAGE_END = """\
</table>
</body>
</html>
"""

ROW_TEMPLATE = """
<tr class="lvl-{record.level} {additional_row_class}">
    <td class="no">{index}</td>
    <td><b style="color: {event_color}">{record.event}</b></td>
    <td class="time"><span title="{time_absolute}" style="{time_color}">{time_display}</span></td>
    <td>{record.logger}</td>
    <td>{record.level}</td>
    <td>{fields}</td>
</tr>
"""


def _colorize_cache_key(value: Any, min_luminance: float) -> Tuple[str, float]:
    if isinstance(value, (list, dict)):
        return repr(value), min_luminance
    return value, min_luminance


@cached(LRUCache(maxsize=2 ** 24))
def rgb_color_picker(obj, min_luminance: float = None, max_luminance: float = None) -> Color:
    """Modified version of colour.RGB_color_picker"""
    color_value = (
        int.from_bytes(hashlib.md5(str(obj).encode("utf-8")).digest(), "little") % 0xFFFFFF
    )
    color = Color(f"#{color_value:06x}")
    if min_luminance and color.get_luminance() < min_luminance:
        color.set_luminance(min_luminance)
    elif max_luminance and color.get_luminance() > max_luminance:
        color.set_luminance(max_luminance)
    return color


def nice_time_diff(time_base: datetime, time_now: datetime) -> Tuple[str, float]:
    delta = time_now - time_base
    total_seconds = delta.total_seconds()
    if total_seconds < 0.001:
        return f"+ {delta.microseconds: 10.0f} µs", total_seconds
    if total_seconds < 1:
        return f"+ {delta.microseconds / 1000: 10.3f} ms", total_seconds
    if total_seconds < 10:
        formatted_seconds = f"{total_seconds: 9.6f}"
        formatted_seconds = f"{formatted_seconds[:6]} {formatted_seconds[6:]}"
        return f"+ {formatted_seconds} s", total_seconds
    return time_now.isoformat(), total_seconds


def get_time_display(prev_record: Optional[Record], record: Record) -> Tuple[str, str, str]:
    time_absolute = record.timestamp.isoformat()
    time_color = ""
    if prev_record:
        time_display, delta_seconds = nice_time_diff(prev_record.timestamp, record.timestamp)
        if delta_seconds <= 10:
            if delta_seconds < 0.0001:  # 100 µs
                time_color_value = COLORMAP[0]
            elif delta_seconds < 1:
                # get color based on duration
                # Normalize range to 100 µs - 1 s (1s = 1.000.000 µs)
                duration_value = delta_seconds * 1_000_000 / 100
                # log10(10_000) == 4
                time_color_value = COLORMAP[int(log10(duration_value) / 4 * 255)]
            else:
                time_color_value = COLORMAP[-1]
            time_color = f"color: {time_color_value}"
    else:
        time_display = time_absolute
    return time_absolute, time_color, time_display


@cached(LRUCache(maxsize=2 ** 24), key=_colorize_cache_key)
def colorize_value(value: Any, min_luminance: float) -> Union[str, list, tuple, dict]:
    if isinstance(value, (list, tuple)):
        return type(value)(colorize_value(inner, min_luminance) for inner in value)
    elif isinstance(value, dict):
        return {
            colorize_value(k, min_luminance): colorize_value(v, min_luminance)
            for k, v in value.items()
        }
    str_value = str(value)
    color = rgb_color_picker(str_value, min_luminance=min_luminance)
    return f'<span style="color: {color.web}">{escape(str_value)}</span>'


def render_fields(record: Record, sorted_known_fields: List[str]) -> List[str]:
    rendered_fields = []
    for field_name in sorted_known_fields:
        if field_name not in record.fields:
            continue
        field_value = record.fields[field_name]
        colorized_value = str(colorize_value(field_value, min_luminance=0.6))
        rendered_fields.append(f'<span class="fn">{field_name}</span> = {colorized_value}')
    return rendered_fields


def parse_log(log_file: TextIO) -> Tuple[List[Record], CounterType[int]]:
    known_fields: CounterType[int] = Counter()
    log_records = []
    last_ts = TIME_PAST
    for i, line in enumerate(log_file, start=1):
        try:
            line_dict = json.loads(line.strip())
        except JSONDecodeError as ex:
            click.secho(f"Error parsing line {i}: {ex}")
            continue

        timestamp_str = line_dict.pop("timestamp", None)
        if timestamp_str:
            timestamp = last_ts = datetime.fromisoformat(timestamp_str)
        else:
            timestamp = last_ts

        log_records.append(
            Record(
                line_dict.pop("event"),
                timestamp,
                line_dict.pop("logger", "MISSING"),
                line_dict.pop("level", "MISSING"),
                line_dict,
            )
        )
        for field_name in line_dict.keys():
            known_fields[field_name] += 1

    return log_records, known_fields


def filter_records(
    log_records: Iterable[Record],
    *,
    drop_events: Set[str],
    keep_events: Set[str],
    drop_loggers: Set[str],
    time_range: Tuple[datetime, datetime],
) -> Generator[Optional[Record], None, None]:
    time_from, time_to = time_range
    for record in log_records:
        event_name = record.event.lower()
        drop = (
            (
                (drop_events and event_name in drop_events)
                or (keep_events and event_name not in keep_events)
            )
            or record.logger in drop_loggers
            or record.timestamp < time_from
            or record.timestamp > time_to
        )
        if drop:
            yield None
        else:
            yield record


def transform_records(
    log_records: Iterable[Optional[Record]], replacements: Dict[str, Any]
) -> Generator[Record, None, None]:
    def replace(value: Any) -> Any:
        # Use `type(value)()` construction to preserve exact (sub-)type
        if isinstance(value, tuple) and hasattr(value, "_fields"):
            # namedtuples have a different signature, *sigh*
            return type(value)(*[replace(inner) for inner in value])
        if isinstance(value, (list, tuple)):
            return type(value)(replace(inner) for inner in value)
        elif isinstance(value, dict):
            return {replace(k): replace(v) for k, v in value.items()}
        str_value = str(value).lower()
        if isinstance(value, str):
            keys_in_value = [key for key in replacement_keys if key in str_value]
            for key in keys_in_value:
                try:
                    repl_start = str_value.index(key)
                except ValueError:
                    # Value no longer in string due to replacement
                    continue
                value = f"{value[:repl_start]}{replacements[key]}{value[repl_start + len(key):]}"
                str_value = value.lower()
        return replacements.get(str_value, value)

    replacements = {str(k).lower(): v for k, v in replacements.items()}
    for k, v in copy(replacements).items():
        # Special handling for `pex()`ed eth addresses
        if isinstance(k, str) and k.startswith("0x") and is_address(k):
            replacements[pex(to_canonical_address(k))] = v
    replacement_keys = replacements.keys()
    for record in log_records:
        yield replace(record)


def render(
    name: str,
    log_records: Iterable[Record],
    known_fields: Counter,
    output: TextIO,
    wrap: bool = False,
    show_time_diff: bool = True,
    highlight_records: Optional[Iterable[int]] = (),
) -> None:
    sorted_known_fields = [name for name, count in known_fields.most_common()]
    highlight_records_set = set(highlight_records) if highlight_records else set()
    prev_record = None
    output.write(PAGE_BEGIN.format(name=name, date=datetime.now()))
    if wrap:
        field_joiner = "<br/>"
    else:
        field_joiner = " "
    for i, record in enumerate(log_records):
        if record is None:
            # We still want to count dropped records
            continue
        time_absolute, time_color, time_display = get_time_display(prev_record, record)
        event_color = rgb_color_picker(record.event, min_luminance=0.6)
        rendered_fields = render_fields(record, sorted_known_fields)
        output.write(
            ROW_TEMPLATE.format(
                index=i,
                record=record,
                time_absolute=time_absolute,
                time_display=time_display,
                time_color=time_color,
                event_color=event_color,
                fields=field_joiner.join(rendered_fields),
                additional_row_class="highlight" if i in highlight_records_set else "",
            )
        )
        if show_time_diff:
            # Without a previous record time diffing will not be applied
            prev_record = record
    output.write(PAGE_END)


@click.command(help=__doc__)
@click.argument("log-file", type=click.File("rt"))
@click.option("-o", "--output", type=click.File("wt"), default="-", show_default=True)
@click.option(
    "-e",
    "--drop-event",
    "drop_events",
    multiple=True,
    help=(
        "Filter out log records with the given event. "
        "Case insensitive. Can be given multiple times."
    ),
)
@click.option(
    "--keep-event",
    "keep_events",
    multiple=True,
    help=(
        "Only keep log records with the given event. Case insensitive. "
        "Can be given multiple times. Cannot be used together with with --drop-event."
    ),
)
@click.option(
    "-l",
    "--drop-logger",
    "drop_loggers",
    multiple=True,
    help=(
        "Filter out log records with the given logger name. "
        "Case insensitive. Can be given multiple times."
    ),
)
@click.option(
    "-r",
    "--replacements",
    help=(
        "Replace values before rendering. "
        "Input must be a JSON object. "
        "Keys are transformed to lowercase strings before matching. "
        "Partial substring matches will also be replaced. "
        "Eth-Addresses will also be replaced in pex()ed format."
    ),
)
@click.option(
    "-f",
    "--replacements-from-file",
    type=click.File("rt"),
    help="Behaves as -r / --replacements but reads the JSON object from the given file.",
)
@click.option(
    "-t",
    "--time-range",
    default="^",
    help=(
        "Specify a time range of log messages to process. "
        'Format: "[<from>]^[<to>]", both in ISO8601'
    ),
)
@click.option(
    "--time-diff/--no-time-diff",
    default=True,
    help="Display log record timestamps relative to previous lines (absolute on hover)",
    show_default=True,
)
@click.option(
    "-w", "--wrap", is_flag=True, help="Wrap event details into multiple lines.", show_default=True
)
@click.option(
    "-h",
    "--highlight-record",
    "highlight_records",
    multiple=True,
    type=int,
    help="Highlight record with given number. Can be given multiple times.",
)
def main(
    log_file: TextIO,
    drop_events: List[str],
    keep_events: List[str],
    drop_loggers: List[str],
    replacements: str,
    replacements_from_file: TextIO,
    time_range: str,
    wrap: bool,
    time_diff: bool,
    highlight_records: List[int],
    output: TextIO,
) -> None:
    if replacements_from_file:
        replacements = replacements_from_file.read()
    if not replacements:
        replacements = "{}"
    try:
        replacements_dict = json.loads(replacements)
    except (JSONDecodeError, UnicodeDecodeError) as ex:
        raise UsageError(f"Option '--replacements' contains invalid JSON: {ex}") from ex

    if drop_events and keep_events:
        raise UsageError(f"Options '--keep-event' and '--drop-event' cannot be used together.")

    time_from, _, time_to = time_range.partition("^")
    time_range_dt = (
        datetime.fromisoformat(time_from) if time_from else TIME_PAST,
        datetime.fromisoformat(time_to) if time_to else TIME_FUTURE,
    )

    click.secho(f"Processing {click.style(log_file.name, fg='yellow')}", fg="green")
    log_records, known_fields = parse_log(log_file)

    prog_bar = click.progressbar(
        log_records, label=click.style("Rendering", fg="green"), file=_default_text_stderr()
    )
    with prog_bar as log_records_progr:
        render(
            log_file.name,
            transform_records(
                filter_records(
                    log_records_progr,
                    drop_events=set(d.lower() for d in drop_events),
                    keep_events=set(k.lower() for k in keep_events),
                    drop_loggers=set(l.lower() for l in drop_loggers),
                    time_range=time_range_dt,
                ),
                replacements=replacements_dict,
            ),
            known_fields=known_fields,
            output=output,
            wrap=wrap,
            show_time_diff=time_diff,
            highlight_records=highlight_records,
        )
    click.secho(f"Output written to {click.style(output.name, fg='yellow')}", fg="green")


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
