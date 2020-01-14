#!/usr/bin/env bash
SCENARIO_REMOTE_URL="http://68.183.70.168:8000/scenario-player/scenarios/"
CURL_COMMAND="curl --silent"
WGET_DIR="wget --no-parent --no-clobber --continue -nH -r"

COLUMNS=$(/usr/bin/tput cols)

### STYLES: IGNORE
RESET="\e[0m"
BOLD="\e[1m"
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

function print_bold {
    echo -e "${BOLD}$1${RESET}"
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

print_bold "Downloading PFS logs"

ssh root@services-dev.raiden.network 'cd raiden-services/deployment/; docker-compose logs pfs-goerli | gzip' > ${DESTINATION_DIR}/pfs.log.gz
if [[ $? -ne 0 ]]; then
    echo "Error: failed to download PFS logs"
    exit 1
fi

print_bold "Downloading scenarios list"

function separator {
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
}

function download_nodes_logs {
    scenario=$1
    run_number=$2
    nodes=$(${CURL_COMMAND} ${SCENARIO_REMOTE_URL}${scenario} | sed -e 's/<[^>]*>//g' | grep -v Directory | sed -e '/^$/d' | grep "^node_${run_number}")
    for node in $nodes; do
        $(${WGET_DIR} -q -P ${DESTINATION_DIR} ${SCENARIO_REMOTE_URL}${scenario}${node})
    done
}

scenarios=$(${CURL_COMMAND} ${SCENARIO_REMOTE_URL} | sed -e 's/<[^>]*>//g' | grep -v Directory | sed -e '/^$/d')

for scenario in $scenarios; do
    run_number=$(${CURL_COMMAND} "${SCENARIO_REMOTE_URL}${scenario}run_number.txt")
    download_nodes_logs $scenario $run_number
    echo -e "\t - ${scenario}, run_number: ${run_number}"
done;

separator

echo -e "${BOLD}Looking for failures${RESET}"
scenarios_dir="${DESTINATION_DIR}/scenario-player/scenarios"
for scenario in $scenarios; do
    print_bold ${scenario}
    separator
    scenario_dir=${scenarios_dir}/${scenario}
    for node in $(ls $scenario_dir); do
        node_dir="${scenario_dir}/${node}/"
        result=$(cat ${node_dir}*.log | jq --tab 'select (.error!=null)')
        if [[ $result != "" ]]; then
            print_bold "- Found error in ${node_dir}"
            echo -e "${result}"
        fi
    done
    separator
done;
