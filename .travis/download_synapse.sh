#!/usr/bin/env bash

set -e
set -x

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


[ -z "${SYNAPSE_URL}" ] && fail 'missing SYNAPSE_URL'
[ -z "${SYNAPSE_SERVER_NAME}" ] && fail 'missing SYNAPSE_SERVER_NAME'

INSTALL_OPT=""
if [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
    # install into user dir on macos to avoid sudo
    INSTALL_OPT="--user"
fi

sudo pip2 install --upgrade setuptools
sudo pip2 install $SYNAPSE_URL

mkdir -p $HOME/.synapse
pwd
cp $HOME/raiden-network/raiden/raiden/tests/test_files/synapse-config.yaml $HOME/.synapse/config

alias run-synapse="python2 -m synapse.homeserver.app --server-name=${SYNAPSE_SERVER_NAME} --config-path=${HOME}/.synapse/config"
cd $HOME/.synapse
run-synapse --generate-keys

info 'installed synapse'
