#!/bin/bash
set -e

DEBUG_LOG_FILE=$1;
OUTPUT_FOLDER=$2;
PWD=`dirname $0`

NODE_ADDRESS=`cat $DEBUG_LOG_FILE | jq .node | sort -u`

if [[ $# != 2 ]]; then
    echo "Usage: $0 <log_file> <output_folder>"
    exit 1;
fi;

mkdir -p $OUTPUT_FOLDER

for node in $NODE_ADDRESS; do
    address=`echo $node | tr -d '"'`
    node_folder=${OUTPUT_FOLDER}/${address}
    full_log=${node_folder}/full.log
    state_machine_log=${node_folder}/state_machine.log
    state_change_timestamps=${node_folder}/state_change_timestamps.log

    echo "Processing ${address}"
    mkdir -p $node_folder
    cat ${DEBUG_LOG_FILE} | jq -c ". | select(.node==${node})" > ${full_log}
    cat ${full_log} | jq -c ". | select((.state_changes | length) > 0 or (.raiden_events | length) > 0)" > ${state_machine_log}

    python $PWD/state_machine_report.py ${state_machine_log} > ${state_change_timestamps}
done;
