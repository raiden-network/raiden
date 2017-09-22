#!/usr/bin/env bash

set -e

fail() {
    if [[ $- == *i* ]]; then
       red=`tput setaf 1`
       reset=`tput sgr0`

       echo "${red}==> ${@}${reset}"
    fi
    exit 1
}

info() {
    if [[ $- == *i* ]]; then
        blue=`tput setaf 4`
        reset=`tput sgr0`

        echo "${blue}${@}${reset}"
    fi
}

success() {
    if [[ $- == *i* ]]; then
        green=`tput setaf 2`
        reset=`tput sgr0`
        echo "${green}${@}${reset}"
    fi

}

warn() {
    if [[ $- == *i* ]]; then
        yellow=`tput setaf 3`
        reset=`tput sgr0`

        echo "${yellow}${@}${reset}"
    fi
}

[ -z "${SOLC_URL_MACOS}" ] && fail 'missing SOLC_URL_MACOS'
[ -z "${SOLC_VERSION}" ] && fail 'missing SOLC_VERSION'

SOLC_CACHE_PATH=$HOME/.bin/solc-macos-${SOLC_VERSION}
SOLC_PATH=/usr/local/Cellar/solidity/${SOLC_VERSION/v/}/bin/solc

if [ ! -x ${SOLC_CACHE_PATH} ]; then
    # Install verbose to avoid travis "no output" timeout
    brew install -v ${SOLC_URL_MACOS}
    cp ${SOLC_PATH} ${SOLC_CACHE_PATH}
    success "solc ${SOLC_VERSION} installed"
else
    ln -sf ${SOLC_CACHE_PATH} $HOME/.bin/solc
    info 'using cached solc'
fi
