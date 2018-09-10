#!/usr/bin/env python
import json
import os
from datetime import datetime

import click


@click.command()
@click.option(
    '--results-dir',
    required=True,
    help='Directory with output json files from orchestration run.',
)
@click.option('--plot-filename', default='', help='Plot historic data to file.')
def process_results(results_dir, plot_filename):
    results = []

    # TODO: save ip + port information
    for filename in os.listdir(results_dir):
        with open('{}/{}'.format(results_dir, filename), 'r') as f:
            contents = json.load(f)
        if 'timestamps' in contents:
            result = contents['timestamps']
            min_, max_ = result[0], result[-1]
            print("Node {} sent messages from {} to {}".format(
                filename,
                datetime.fromtimestamp(min_).strftime("%H:%M:%S.%f"),
                datetime.fromtimestamp(max_).strftime("%H:%M:%S.%f"),
            ))
            results.append(result)

    min_, max_ = results[0][0], results[0][-1]
    for result in results:
        min_ = min(min_, result[0])
        max_ = max(max_, result[-1])

    print("First transfer was at {}".format(
        datetime.fromtimestamp(min_).strftime("%H:%M:%S.%f")))
    print("Last transfer was at {}".format(
        datetime.fromtimestamp(max_).strftime("%H:%M:%S.%f")))

    for result in results:
        result.reverse()

    initial_time = int(min_)
    last_time = int(max_) + 1

    amount_per_time = [0] * (last_time - initial_time)
    index = 0
    max_amount = (0.0, 0)
    for time in range(initial_time, last_time):
        for result in results:
            while len(result) > 0 and result[-1] < time + 1.0:
                result.pop()
                amount_per_time[index] += 1
        print("Total transfers from {} to {} was {}".format(
            datetime.fromtimestamp(time).strftime("%H:%M:%S"),
            datetime.fromtimestamp(time + 1).strftime("%H:%M:%S"),
            amount_per_time[index],
        ))
        if amount_per_time[index] > max_amount[1]:
            max_amount = (time, amount_per_time[index])
        index += 1

    print("Maximum transfers happened from {} to {} and was {}".format(
        datetime.fromtimestamp(max_amount[0]).strftime("%H:%M:%S"),
        datetime.fromtimestamp(max_amount[0] + 1).strftime("%H:%M:%S"),
        max_amount[1],
    ))

    times = [time for time in range(initial_time, last_time)]  # + 1 ?

    if plot_filename:
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            import matplotlib.dates as md
            print("Writing plot to '{}'...".format(plot_filename))
            dates = [datetime.fromtimestamp(ts) for ts in times]
            plt.subplots_adjust(bottom=0.2)
            plt.xticks(rotation=90)
            ax = plt.gca()
            # ax.set_xticks(dates)
            xfmt = md.DateFormatter('%H:%M:%S')
            ax.xaxis.set_major_formatter(xfmt)
            plt.plot(dates, amount_per_time)
            plt.savefig(plot_filename)
        except ImportError as exc:
            print("Error creating plot results: {}".format(exc))


if __name__ == '__main__':
    process_results()
