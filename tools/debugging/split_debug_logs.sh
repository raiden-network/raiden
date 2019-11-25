#!/bin/bash

# This script will read a `raiden-debug*.log` file and fiter the logs by the
# `node` attribute for easier debugging.
#
# Sadly this cannot be done with the logging system in python without a lot of
# hacking around, because the log instances are always global, shared across
# all the nodes in the test, which are executed within the same process
# (Running all nodes on the same process makes it easier to use a debugger).

set -e

usage() {
    echo "$0 <raiden-debug-log> <output-dir>"
    exit 1
}

DEBUG_LOG_FILE=$1;
OUTPUT_FOLDER=$2;
PWD=`dirname $0`

[ $# -ne 2 ] && {
    echo 'Invalid number of arguments.'
    echo
    usage
}

[ ! -f "${DEBUG_LOG_FILE}" ] && {
    echo "The argument '${DEBUG_LOG_FILE}' must be a log file"
    echo
    usage
}

[ ! -e "${OUTPUT_FOLDER}" ] && {
    mkdir -p "${OUTPUT_FOLDER}"
}

[ ! -d "${OUTPUT_FOLDER}" ] && {
    echo "The argument '${OUTPUT_FOLDER}' must be a directory"
    echo
    usage
}

mkdir -p $OUTPUT_FOLDER

for node_address in $(cat "${DEBUG_LOG_FILE}" | jq -r '.node' | sort -u | grep -v null); do
    node_folder="${OUTPUT_FOLDER}/${node_address}"
    full_log="${node_folder}/full.log"
    state_machine_log="${node_folder}/state_machine.log"
    state_change_timestamps="${node_folder}/state_change_timestamps.log"

    echo "Processing '${node_address}'"
    mkdir -p "${node_folder}"
    cat "${DEBUG_LOG_FILE}" | jq -c "select(.node==\"${node_address}\")" > "${full_log}"
    cat "${full_log}" | jq -c ". | select((.state_changes | length) > 0 or (.raiden_events | length) > 0)" > "${state_machine_log}"

    python $PWD/state_machine_report.py "${state_machine_log}" > "${state_change_timestamps}"
done;

echo "Processing logs without a node address"
jq "select(.node==null)" "${DEBUG_LOG_FILE}" > "${OUTPUT_FOLDER}/unknown.log"
