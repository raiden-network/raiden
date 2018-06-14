#!/usr/bin/env bash

set -e
set -x


if [ -z "${SYNAPSE_URL}" ]; then
    SYNAPSE_URL='https://github.com/matrix-org/synapse/tarball/master#egg=matrix-synapse'
fi

if [ -z "${SYNAPSE_SERVER_NAME}" ]; then
    SYNAPSE_SERVER_NAME='matrix.local.raiden'
fi


if [ -z "${TRAVIS}" ]; then
    if [ -z "${BASEDIR}" ]; then
        BASEDIR=$(dirname $(dirname $(readlink -m $0)))
    fi
else
    BASEDIR=${HOME}/build/raiden-network/raiden
    if [[ "${TRAVIS_OS_NAME}" == "linux" ]]; then
        sudo apt-get -qq update
        sudo apt-get install -y sqlite3
    fi
fi


mkdir -p ${BASEDIR}/.synapse

virtualenv -p $(which python2) ${BASEDIR}/.synapse/venv
${BASEDIR}/.synapse/venv/bin/pip install $SYNAPSE_URL

cp ${BASEDIR}/raiden/tests/test_files/synapse-config.yaml ${BASEDIR}/.synapse/config.yml
${BASEDIR}/.synapse/venv/bin/python -m synapse.app.homeserver --server-name=${SYNAPSE_SERVER_NAME} \
	--config-path=${BASEDIR}/.synapse/config.yml --generate-keys

echo """
#!/usr/bin/env bash
cd ${BASEDIR}/.synapse
venv/bin/python -m synapse.app.homeserver --server-name=${SYNAPSE_SERVER_NAME} \
  --config-path=${BASEDIR}/.synapse/config.yml
""" > ${BASEDIR}/.synapse/run.sh
chmod 775 ${BASEDIR}/.synapse/run.sh
