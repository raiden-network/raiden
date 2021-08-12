#!/usr/bin/env python
import argparse
import csv
import datetime
import sys
from typing import Any, List

from matplotlib import dates, pyplot
from matplotlib.axes import Axes


parser = argparse.ArgumentParser()
parser.add_argument("--width", default=1000, help="Configures width of the output in pixels.")
parser.add_argument("--height", default=800, help="Configures height of the output in pixels.")
parser.add_argument(
    "--header", help="If the csv does not have a header, use this to give a name to each column"
)
parser.add_argument(
    "output", help="file name for the result image, filetype is inferred from this."
)
parser.add_argument(
    "--x", help="If set, the name of the column to be used as the x axis", default=None
)
parser.add_argument("line", nargs="+")

args = parser.parse_args()


def parse_datetime(data: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(data)


def configure_axes(axes: Axes) -> None:
    hour_fmt = dates.DateFormatter("%H:%M")
    minutes_fmt = dates.DateFormatter("%M")

    axes.xaxis.set_major_locator(dates.HourLocator(interval=1))
    axes.xaxis.set_major_formatter(hour_fmt)
    axes.xaxis.set_minor_locator(dates.MinuteLocator(interval=5))
    axes.xaxis.set_minor_formatter(minutes_fmt)
    axes.xaxis.set_tick_params(which="major", rotation=90)
    axes.xaxis.set_tick_params(which="minor", rotation=90)


if args.header:
    headers = args.header.split(",")
    reader = csv.DictReader(sys.stdin, fieldnames=headers)
else:
    reader = csv.DictReader(sys.stdin)

lines: List[List[Any]] = [[] for _ in range(len(args.line))]

x_axis: List[Any]
if args.x:
    x_axis = []
    for data in reader:
        x_axis.append(parse_datetime(data[args.x]))

        for pos, line in enumerate(args.line):
            lines[pos].append(float(data[line]))
else:
    for data in reader:
        for pos, line in enumerate(args.line):
            lines[pos].append(float(data[line]))

    x_axis = list(range(len(lines[0])))


dpi = 60
pyplot.figure(figsize=(args.width / dpi, args.height / dpi), dpi=dpi)

axes = pyplot.gca()
axes.set_xlabel(args.x)
configure_axes(axes)

for line_name, line_data in zip(args.line, lines):
    pyplot.plot(x_axis, line_data, label=line_name)

pyplot.legend(loc=2)
pyplot.savefig(args.output)
