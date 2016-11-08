#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json

def plot_results(results_dir):
    results = []

    # TODO: save ip + port information
    for filename in os.listdir(results_dir):
        with open('{}/{}'.format(results_dir, filename), 'r') as f:
            contents = json.load(f)
        if 'timestamps' in contents:
            results.append(contents['timestamps'])

    min_, max_ = results[0][0], results[0][-1]
    for result in results:
        min_ = min(min_, result[0])
        max_ = max(max_, result[-1])

    # because O(log(N))
    for result in results:
        result.reverse()

    initial_time = int(min_)
    last_time = int(max_) + 1

    amount_per_time = [0] * (last_time - initial_time)
    index = 0
    for time in xrange(initial_time, last_time):
        for result in results:
            while len(result) > 0 and result[-1] < time + 1.0:
                result.pop()
                amount_per_time[index] += 1
        index += 1

    #print(amount_per_time)
    times = [time for time in xrange(initial_time, last_time)]  # + 1 ?

    # TODO: also save contents to text report

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.dates as md
        from datetime import datetime
        dates = [datetime.fromtimestamp(ts) for ts in times]
        ax = plt.gca()
        xfmt = md.DateFormatter('%H:%M:%S')
        ax.xaxis.set_major_formatter(xfmt)
        plt.plot(dates, amount_per_time)
        plt.savefig('results.png')
    except ImportError:
        pass

if __name__ == '__main__':
    plot_results('results')  # FIXME
