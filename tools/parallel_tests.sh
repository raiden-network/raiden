#!/usr/bin/env bash

set -e

# shellcheck source=tools/_compat.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"/_compat.sh

split_command=$(get_coreutils_command split)
# make sure we're using the correct executable (inside tmux)
python_exe=$(python -c "import sys; print(sys.executable)")

PARALLELISM=${PARALLELISM:-$(python -c "import os; print(os.cpu_count())")}
# Only used with tmux. Useful tmux layout names:
# 'even-horizontal', 'even-vertical', 'tiled'
LAYOUT=${LAYOUT:-even-vertical}

tmpdir=$(mktemp -d)
alltest=${tmpdir}/all_test
output=${tmpdir}/sessions
logs=${tmpdir}/logs
session_prefixes="${output}/raiden-tests"
base_port=10500

echo "Tests files located at ${tmpdir}"

mkdir -p "${output}" "${logs}"

pytest --quiet --collect-only "$@" | grep :: > "${alltest}"
${split_command} --number "l/${PARALLELISM}" --numeric-suffixes "${alltest}" "${session_prefixes}"

if (type tmux &> /dev/null); then
    if [[ ${LAYOUT} == even-vertical ]]; then
        rows=$(tput lines)
        # 'even-vertical' needs 3 rows per pane + 1 border in-between + 1 bottom bar
        rows_needed=$(( (3 * PARALLELISM) + (PARALLELISM - 1) + 1 ))
        if [[ ${rows_needed} -gt ${rows} ]]; then
            echo "Not enough rows in terminal window, using 'tiled' layout."
            LAYOUT="tiled"
        fi
    fi

    declare -a args
    idx=0
    for f in "${session_prefixes}"*; do
        if [[ ${idx} -eq 0 ]]; then
            args+=(new-session)
        else
            args+=(split-window)
        fi
        logfile=$(basename "${f}")
        args+=("${python_exe} -m pytest raiden/tests --select-from-file ${f} -v --color yes --base-port $(( base_port + ( idx * 500) )) | tee -a ${logs}/${logfile}; echo 'Ctrl-C to exit'; read")
        args+=(";")
        args+=("select-layout" "${LAYOUT}" ";")
        idx=$(( idx + 1 ))
    done
    args+=("select-layout" "${LAYOUT}" ";")
    args+=("setw" "mouse" "on")
    echo "${args[@]}"
    tmux -v "${args[@]}"
else
    trap '[[ $(jobs -p | wc -l) -gt 0 ]] && kill $(jobs -p) || true' EXIT
    echo 'Warning: tmux not available. Test output will only be written to files.'

    idx=0
    for f in "${session_prefixes}"*; do
        logfile=$(basename "${f}")
        pytest raiden/tests --select-from-file "${f}" -v --base-port $(( base_port + ( idx * 1000) )) > "${logs}/${logfile}" &
        idx=$(( idx + 1 ))
    done
    wait  # wait for all tests to run
fi

exit $?
