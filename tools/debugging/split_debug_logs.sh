#!/usr/bin/env bash

# This script will read a `raiden-debug*.log` file and fiter the logs by the
# `node` attribute for easier debugging.
#
# Sadly this cannot be done with the logging system in python without a lot of
# hacking around, because the log instances are always global, shared across
# all the nodes in the test, which are executed within the same process
# (Running all nodes on the same process makes it easier to use a debugger).

set -eo pipefail

usage() {
    echo "$0 <raiden-debug-log> <output-dir>"
    exit 1
}

process_node_log() {
    node_address="$1"
    echo "Processing '${node_address}'"

    node_folder="${OUTPUT_FOLDER}/${node_address}"
    full_log="${node_folder}/full.log"
    state_machine_log="${node_folder}/state_machine.log"
    state_change_timestamps="${node_folder}/state_change_timestamps.log"

    mkdir -p "${node_folder}"

    jq -c "select(.node==\"${node_address}\")" "${DEBUG_LOG_FILE}" > "${full_log}"
    jq -c "select((.state_changes | length) > 0 or (.raiden_events | length) > 0)" "${full_log}" > "${state_machine_log}"
    "${SCRIPT_DIR}"/state_machine_report.py "${state_machine_log}" > "${state_change_timestamps}"
}

[ $# -ne 2 ] && {
    echo 'Invalid number of arguments.'
    echo
    usage
}

DEBUG_LOG_FILE="$1";
OUTPUT_FOLDER="$2";
# Get script dir independent of calling location
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)
# Make sure we continue to use the same shell in subshells (b/c of sem below)
SHELL="${BASH}"

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

mkdir -p "${OUTPUT_FOLDER}"

# Those will be used in the subshell via parallel / sem
export DEBUG_LOG_FILE OUTPUT_FOLDER SCRIPT_DIR SHELL
export -f process_node_log

jq -r '.node' "${DEBUG_LOG_FILE}" | (grep -v null || true) | sort -u | \
parallel process_node_log

echo "Processing logs without a node address"
jq "select(.node==null)" "${DEBUG_LOG_FILE}" > "${OUTPUT_FOLDER}/unknown.log"
