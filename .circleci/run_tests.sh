#!/usr/bin/env bash

set -e
set -x

test_report_dir=$1
blockchain_type=$2

# Remove the above arguments, every thing extra will be passed down to coverage
shift 2

mkdir -p ${test_report_dir}

# Using 9min as the dormant timeout, CircleCI will kill the container after
# 10min
# https://support.circleci.com/hc/en-us/articles/360007188574-Build-has-hit-timeout-limit
#
# This value should be larger than our tests timeout configuration, the default
# is defined at setup.cfg under the section `[tool:pytest]`.
dormant_timeout=570

# This signal is installed in
# raiden/tests/conftest.py::auto_enable_gevent_monitoring_signal
dormant_signal=SIGUSR1

./tools/kill_if_no_output.py \
    --dormant-timeout=${dormant_timeout} \
    --dormant-signal=${dormant_signal} \
    --kill-timeout=15 \
    --kill-signal=SIGKILL \
    coverage \
    run \
    --include="~/raiden/**/*" \
    --parallel-mode \
    --module pytest \
    raiden/tests \
    -vvvvvv \
    --color=yes \
    --log-config='raiden:DEBUG' \
    --random \
    --junit-xml=${test_report_dir}/results.xml \
    --blockchain-type=${blockchain_type} \
    --select-fail-on-missing \
    --select-from-file selected-tests.txt \
    "${@}"

if [ -n ${RAIDEN_TESTS_LOGSDIR} ]; then
    # Enable nullglob, otherwise the loop bellow would do one iteration
    # over the pattern, leading to a failure, since the pattern is not a
    # valid file.
    shopt -s nullglob

    for test_directory in ${RAIDEN_TESTS_LOGSDIR}/*; do
        # Pytest's paremetrize tests have brackets in their names, e.g.
        # `test_api_open_channel_invalid_input[matrix-False-0-1]`, the
        # expression bellow must have the test_directory variable in quotes to
        # prevent the shell from trying to expand the brackets
        for log_file in "${test_directory}"/raiden-debug*.log; do
            ./tools/debugging/split_debug_logs.sh "${log_file}" "${test_directory}/node_logs/"
        done
    done
fi
