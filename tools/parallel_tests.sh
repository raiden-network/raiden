#!/usr/bin/env bash

set -e

split_command=split
if [[ $(uname -s) == Darwin ]]; then
    if ! (type gsplit &> /dev/null); then
        echo -e "GNU split is required. Install with:\n    brew install coreutils"
        exit 1
    fi
    split_command=gsplit
fi

PARALLELISM=${PARALLELISM:-4}
# Only used with tmux. Useful tmux layout names:
# 'even-horizontal', 'even-vertical', 'tiled'
LAYOUT=${LAYOUT:-even-vertical}

tmpdir=$(mktemp -d)
alltest=${tmpdir}/all_test
output=${tmpdir}/sessions
logs=${tmpdir}/logs
session_prefixes="${output}/raiden-tests"
synapse_base_port=10500

echo "Tests files located at ${tmpdir}"

mkdir -p ${output} ${logs}

pytest --quiet --collect-only "$@" | grep :: > ${alltest}
${split_command} --number "l/${PARALLELISM}" --numeric-suffixes ${alltest} ${session_prefixes}

if (type tmux &> /dev/null); then
    if [[ ${LAYOUT} == even-vertical ]]; then
        rows=$(tput lines)
        # 'even-vertical' needs 3 rows per pane + 1 border in-between + 1 bottom bar
        rows_needed=$(( (3 * ${PARALLELISM}) + (${PARALLELISM} - 1) + 1 ))
        if [[ ${rows_needed} -gt ${rows} ]]; then
            echo "Not enough rows in terminal window, using 'tiled' layout."
            LAYOUT="tiled"
        fi
    fi

    declare -a args
    idx=0
    for f in ${session_prefixes}*; do
        if [[ ${idx} -eq 0 ]]; then
            args+=(new-session)
        else
            args+=(split-window)
        fi
        logfile=$(basename ${f})
        args+=("pytest raiden/tests --select-from-file ${f} -v --color yes --synapse-base-port $(( ${synapse_base_port} + ( ${idx} * 1000) )) | tee ${logs}/${logfile}; echo 'Ctrl-C to exit'; read")
        args+=(";")
        args+=("select-layout" "${LAYOUT}" ";")
        idx=$(( $idx + 1 ))
    done
    args+=("select-layout" "${LAYOUT}" ";")
    args+=("setw" "mouse" "on")
    echo ${args[@]}
    tmux -v "${args[@]}"
else
    trap '[[ $(jobs -p | wc -l) -gt 0 ]] && kill $(jobs -p) || true' EXIT
    echo 'Warning: tmux not available. Test output will only be written to files.'

    idx=0
    for f in ${session_prefixes}*; do
        logfile=$(basename ${f})
        pytest raiden/tests --select-from-file ${f} -v --synapse-base-port $(( ${synapse_base_port} + ( ${idx} * 1000) )) > ${logs}/${logfile} &
        idx=$(( $idx + 1 ))
    done
    wait  # wait for all tests to run
fi

exit $?
