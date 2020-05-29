#!/usr/bin/env bash

cd /var/lib/scenario-player;
source env.sh

find_in_array() {
    local word=$1
    shift
    for entry in "$@"; do [[ "$entry" == "$word" ]] && return 0; done
    return 1
}

cd "${DATA_DIR}"/scenarios;
for scenario_path in "$SCENARIOS_DIR"/ci/"$SP"/*.yaml; do
    scenario_file=$(basename "$scenario_path")
    scenario=${scenario_file//.yaml}

    find_in_array $scenario "$@" || {
        run=$(cat "${scenario}"/run_number.txt)

        find "$scenario"/node_"$run"_*
        ls "$scenario"/scenario-player-run* -1 -t | head -1
    }
done | tar zcf - -T -
