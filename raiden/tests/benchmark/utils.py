

def print_serialization(pstats):  # pylint: disable=too-many-locals
    print('ncalls         tottime  percall  %    cumtime  percall  function')
    total_pct = 0.0

    for path_line_func, data in pstats.sort_stats('module', 'cumulative').stats.items():
        path, line, func = path_line_func  # pylint: disable=unused-variable

        is_rlp = 'rlp' in path
        is_encoding = 'encoding' in path
        if is_rlp or is_encoding:
            # primitive calls dont count recursion
            # total calls count recursion
            # total time is the time for the function itself (excluding subcalls)
            # accumulated_time is the time of the function plus the subcalls
            primitive_calls, total_calls, total_time, acc_time, _ = data

            if primitive_calls != total_calls:
                calls = '{}/{}'.format(total_calls, primitive_calls)
            else:
                calls = str(primitive_calls)

            pct = (total_time / pstats.total_tt) * 100
            total_pct += pct
            print('{:<14} {:<8.3f} {:<8.3f} {:<3.2f} {:<8.3f} {:<8.3f} {}'.format(
                calls,
                total_time,
                total_time / total_calls,
                pct,
                acc_time,
                acc_time / total_calls,
                func,
            ))

    print(' Runtime: {}, Total %: {}'.format(pstats.total_tt, total_pct))


def print_slow_path(pstats):
    pstats.strip_dirs().sort_stats('cumulative').print_stats(15)


def print_slow_function(pstats):
    pstats.strip_dirs().sort_stats('time').print_stats(15)
