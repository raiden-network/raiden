#!/usr/bin/env bash

set -eo pipefail
set -x

# shellcheck source=tools/_compat.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"/_compat.sh
readlink_command=$(get_coreutils_command readlink)

SCENARIO_REMOTE_URL_1="root@scenario-player.ci.raiden.network"
SCENARIO_REMOTE_URL_2="root@scenario-player2.ci.raiden.network"

COLUMNS=$(/usr/bin/tput cols)
RESET=$(/usr/bin/tput init)
BOLD=$(/usr/bin/tput bold)
DIR="$(dirname "$($readlink_command -f "$0")")"

function print_bold {
    echo -e "${BOLD}$1${RESET}"
}

function separator {
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
}

function display_usage {
    echo "This script does the following:"
    echo "1. Figures out the run number of each of the existing scenarios"
    echo "2. Downloads the logs for each of the nodes involved in the latest scenario run"
    echo "3. Looks through the logs and searches for errors / exceptions and reports them"
    echo -e "\n\nUSAGE: extract_sp_exceptions.sh [DESTINATION_DIR]\n"
    echo -e "Where\n"
    echo -e "\tDESTINATION_URL is optional and is used to specify the path prefix for the downloaded files. Otherwise the current directory is used\n"
}

die() {
    printf "$(tput bold)$(tput setaf 1) -> %s$(tput sgr0)\n" "$1" >&2
    exit 1
}

require_bin() {
    hash "$1" 2> /dev/null || {
        die "Required binary was not found ${1}"
    }
}

require_bin pv
require_bin scp
require_bin ssh
require_bin gunzip

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
SCENARIOS_DIR="$DESTINATION_DIR"/scenarios

function download_service_logs {
    sources=()

    for file in "$@"; do
        if [[ ! -e "${DESTINATION_DIR}/${file}" ]]; then
            sources+=("root@services-dev.raiden.network:/home/services/${file}")
        fi
    done

    if [[ "${#sources[@]}" -gt 0 ]]; then
        scp "${sources[@]}" "${DESTINATION_DIR}"
    fi
}

function download_server_logs {
    current_server=$1

    (
        cd "${SCENARIOS_DIR}" || die "SCENARIOS_DIR missing"

        # The echo is used to remove the newline character
        # shellcheck disable=SC2005,SC2046
        local_files=$(echo $(ls))

        # `ssh` will execute `bash` on the remote, with the flags `-s -` bash
        # will read the commands from the `stdin`, and the arguments
        # `$local_files` are passed as position arguments to the script.
        #
        # This allows the remote to filter out files that have already been
        # downloaded.
        # shellcheck disable=SC2002
        cat "$DIR"/sp_download_scenario_logs.sh \
            | ssh "$current_server" bash -s - "$local_files" \
            | pv \
            | tar zxf -
    )
}

function search_for_failures {
    mkdir -p "${DESTINATION_DIR}/errors/"
    echo -e "${BOLD}Looking for failures${RESET}"

    for scenario_logs in "${SCENARIOS_DIR}"/**/scenario-player*.log.gz ; do
        scenario_successful=$(gunzip -c  "$scenario_logs" | jq 'select(.result == "success")')

        if [ -z "${scenario_successful}" ]; then
            scenario=$(basename "${scenario_logs}")
            scenario_dir=$(dirname "${scenario_logs}")

            separator
            print_bold "Scenario ${scenario} failed"
            gunzip -c  "$scenario_logs" | jq 'select(.result != null) | .message'
            separator

            for node_dir in "${scenario_dir}"/node_* ; do
                gunzip -c "${node_dir}"/*.log.gz | jq --tab 'select (.error!=null or .exception!=null)'
                cat "${node_dir}"/*.stderr | grep -v Starting | grep -v Stopped
            done

            separator

            gunzip -c "${scenario_dir}"/scenario-player-run_*.log.gz | jq 'select (.error!=null or .exception!=null)'
        fi
    done;
}

mkdir -p "${SCENARIOS_DIR}"

print_bold "Downloading services logs"
download_service_logs ms-goerli-backup.gz ms-goerli.gz msrc-goerli-backup.gz msrc-goerli.gz pfs-goerli-with-fee.gz pfs-goerli.gz

print_bold "Downloading scenarios list"
download_server_logs $SCENARIO_REMOTE_URL_1
download_server_logs $SCENARIO_REMOTE_URL_2

# search_for_failures expects the logs to be compressed
find "${SCENARIOS_DIR}" -type f -iname '*.log' -print0 | xargs -0 gzip -q

search_for_failures
