#!/usr/bin/env bash

set -eo pipefail

cd /var/lib/scenario-player || exit 1;
if [[ -f env.sh ]] ; then
    # shellcheck disable=SC1091
    source env.sh
else
    echo "env.sh is missing"
    exit 1
fi

[[ -n ${DATA_DIR:?missing in env.sh} ]]
[[ -n ${SCENARIOS_DIR:?missing in env.sh} ]]
[[ -n ${SP:?missing in env.sh} ]]

find_in_array() {
    local word=$1
    shift
    for entry in "$@"; do [[ "$entry" == "$word" ]] && return 0; done
    return 1
}

cd "${DATA_DIR}"/scenarios || exit 1;
for scenario_path in "$SCENARIOS_DIR"/ci/"$SP"/*.yaml; do
    scenario_file=$(basename "$scenario_path")
    scenario=${scenario_file//.yaml}

    find_in_array "$scenario" "$@" || {
        run=$(cat "${scenario}"/run_number.txt)

        find "$scenario"/node_"$run"_*
        # shellcheck disable=SC2012
        ls "$scenario"/scenario-player-run* -1 -t | head -1
    }
done | tar zcf - -T -
