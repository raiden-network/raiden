#!/usr/bin/env python
import argparse
import csv
import datetime
import sys

import numpy
from matplotlib import dates, pyplot
from matplotlib.axes import Axes


parser = argparse.ArgumentParser()
parser.add_argument("--width", default=1000, help="Configures width of the output in pixels.")
parser.add_argument("--height", default=800, help="Configures height of the output in pixels.")
parser.add_argument("--x-bins", default=100, help="Configures the number of bins for the x axis.")
parser.add_argument("--y-bins", default=25, help="Configures the number of bins for the y axis.")
parser.add_argument(
    "--header", help="If the csv does not have a header, use this to give a name to each column"
)
parser.add_argument(
    "output", help="file name for the result image, filetype is inferred from this."
)
parser.add_argument("x")
parser.add_argument("y")

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


timestamps = list()
rtts = list()

if args.header:
    headers = args.header.split(",")
    reader = csv.DictReader(sys.stdin, fieldnames=headers)
else:
    reader = csv.DictReader(sys.stdin)

for line in reader:
    timestamps.append(parse_datetime(line[args.x]).timestamp())
    rtts.append(float(line[args.y]))


histogram, x_data, y_data = numpy.histogram2d(timestamps, rtts, bins=[args.x_bins, args.y_bins])
to_datetime = numpy.vectorize(datetime.datetime.fromtimestamp)

dpi = 60
pyplot.figure(figsize=(args.width / dpi, args.height / dpi), dpi=dpi)

axes = pyplot.gca()
axes.set_xlabel(args.x)
axes.set_ylabel(args.y)
configure_axes(axes)

axes.pcolor(to_datetime(x_data), y_data, histogram.T)

pyplot.savefig(args.output)
