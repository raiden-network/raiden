#!/usr/bin/env bash

# Functions for compatibility between GNU and BSD/macOS systems

get_coreutils_command() {
    command_name=$1
    command_name_gprefix="g${command_name}"

    if [[ $(uname -s) == Darwin ]]; then
        if ! (type "${command_name_gprefix}" &> /dev/null); then
            >&2 echo -e "GNU ${command_name} is required. Install with:\n    brew install coreutils"
            exit 1
        fi
        command_name="$command_name_gprefix"
    fi
    echo "$command_name"
}
