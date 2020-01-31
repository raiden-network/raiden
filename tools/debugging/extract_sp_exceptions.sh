#!/usr/bin/env bash

SCENARIO_REMOTE_URL_1="http://scenario-player.ci.raiden.network/scenarios/"
SCENARIO_REMOTE_URL_2="http://scenario-player2.ci.raiden.network/scenarios/"
CURL_COMMAND="curl --silent"
WGET_DIR="wget --no-parent --no-clobber --continue -nH -r"

### STYLES: IGNORE
COLUMNS=$(/usr/bin/tput cols)
RESET=$(/usr/bin/tput init)
BOLD=$(/usr/bin/tput bold)

function print_bold {
    echo -e "${BOLD}$1${RESET}"
}

function separator {
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
}
###

function display_usage {
    echo "This script does the following:"
    echo "1. Figures out the run number of each of the existing scenarios"
    echo "2. Downloads the logs for each of the nodes involved in the latest scenario run"
    echo "3. Looks through the logs and searches for errors / exceptions and reports them"
    echo -e "\n\nUSAGE: extract_sp_exceptions.sh [DESTINATION_DIR]\n"
    echo -e "Where\n"
    echo -e "\tDESTINATION_URL is optional and is used to specify the path prefix for the downloaded files. Otherwise the current directory is used\n"
}


if [[  $1 == "--help" ]]; then
    display_usage
    exit 1
fi

if [[ $1 != "" ]]; then
    DESTINATION_DIR=$1
else
    DESTINATION_DIR=$(pwd)
fi

DESTINATION_DIR="$(realpath -s "${DESTINATION_DIR}")/$(date +%m-%d-%Y)"
mkdir -p "$DESTINATION_DIR"

function download_pfs_logs {
    container=$1
    ssh root@services-dev.raiden.network "cd raiden-services/deployment/; docker-compose logs ${container} | gzip" > "${DESTINATION_DIR}/${container}.log.gz"
    if [[ $? -ne 0 ]]; then
        echo "Error: failed to download pfs-goerli logs"
        exit 1
    fi
}

function download_nodes_logs {
    scenario=$1
    current_server=$2
    run_number=$3

    nodes=$(${CURL_COMMAND} "${current_server}${scenario}" | grep '^<a ' | cut -d\" -f2 | grep "^node_${run_number}")

    for node in $nodes; do
        ${WGET_DIR} -q -P "${DESTINATION_DIR}" "${current_server}${scenario}${node}" &
    done

    latest_sp_log=$(${CURL_COMMAND} "${current_server}${scenario}" | grep '^<a ' | cut -d\" -f2 | grep ".log.gz$" | sort | tail -n 1)
    ${WGET_DIR} -q -P "${DESTINATION_DIR}" "${current_server}${scenario}${latest_sp_log}" &

    wait
}

function download_server_logs {
    current_server=$1
    scenarios=$(${CURL_COMMAND} "${current_server}" | grep '^<a ' | cut -d\" -f2)
    for scenario in $scenarios; do
        run_number=$(${CURL_COMMAND} "${current_server}${scenario}run_number.txt")
        [ -n "$run_number" ] || { echo 'Could not find run number!'; exit 1; }
        download_nodes_logs "$scenario" "${current_server}" "${run_number}"
        echo -e "\t - ${scenario}, run_number: ${run_number}"
    done;

    separator
}

function search_for_failures {
    mkdir -p "${DESTINATION_DIR}/errors/"
    echo -e "${BOLD}Looking for failures${RESET}"
    scenarios_dir="${DESTINATION_DIR}/scenarios"

    for scenario_dir in "${scenarios_dir}"/*; do
        scenario=$(basename "${scenario_dir}")
        print_bold "${scenario}"
        separator

        for node_dir in $(find "${scenario_dir}" -maxdepth 1 -type d -name "node_*"); do
            result=$(gunzip -c ${node_dir}/*.log.gz | jq --tab 'select (.error!=null or .exception!=null)')
            if [[ $result == "" ]]; then
                result=$(cat "${node_dir}"/*.stderr | grep -v Starting | grep -v Stopped)
            fi
            if [[ $result != "" ]]; then
                print_bold "- Found error in ${node_dir}"
                echo -e "${result}"
                echo "${result}" > "${DESTINATION_DIR}/errors/${scenario}.node.log.gz"
            fi
        done

        separator
        sp_error=$(gunzip -c "${scenario_dir}"/scenario-player-run_*.log.gz | jq 'select (.error!=null or .exception!=null)')

        if [[ $sp_error != "" ]]; then
            print_bold "- SP reported an error in ${scenario_dir}"

            echo -e "${sp_error}"
            echo "${sp_error}" > "${DESTINATION_DIR}/errors/${scenario}.sp.log"
        fi

        separator
    done;
}

# export the symbol to allow the subshell spawned by parallel to use it
export -f download_pfs_logs
export -f download_server_logs

print_bold "Downloading PFS logs"

download_pfs_logs pfs-goerli &
download_pfs_logs pfs-goerli-with-fee &
wait

print_bold "Downloading scenarios list"
download_server_logs $SCENARIO_REMOTE_URL_1
download_server_logs $SCENARIO_REMOTE_URL_2
search_for_failures
