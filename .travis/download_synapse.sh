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

if [[ "${TRAVIS_OS_NAME}" == "linux" ]]; then
    sudo apt-get -qq update
    sudo apt-get install -y sqlite3
fi

if [ -z "${TRAVIS}" ]; then
    BASEDIR=.
else
    BASEDIR=${HOME}/build/raiden-network/raiden
fi



mkdir -p ${BASEDIR}/.synapse

virtualenv -p $(which python2) ${BASEDIR}/.synapse/venv
${BASEDIR}/.synapse/venv/bin/pip install $SYNAPSE_URL

cp ${BASEDIR}/raiden/tests/test_files/synapse-config.yaml ${BASEDIR}/.synapse/config.yml
${BASEDIR}/.synapse/venv/bin/python -m synapse.app.homeserver --server-name=${SYNAPSE_SERVER_NAME} \
	--config-path=.synapse/config.yml --generate-keys

echo """
#!/usr/bin/env bash
cd ${BASEDIR}/.synapse
venv/bin/python -m synapse.app.homeserver --server-name=${SYNAPSE_SERVER_NAME} \
  --config-path=config.yml
""" > ${BASEDIR}/.synapse/run.sh
chmod 775 ${BASEDIR}/.synapse/run.sh
