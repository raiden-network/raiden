#!/usr/bin/env bash

set -ex

SYNAPSE_URL="${SYNAPSE_URL:-https://github.com/matrix-org/synapse/tarball/master#egg=matrix-synapse}"
SYNAPSE_SERVER_NAME="${SYNAPSE_SERVER_NAME:-matrix.local.raiden}"
BASEDIR=$(readlink -m "$(dirname $0)/..")

if [ ! -d "${DESTDIR}" ]; then
    if [ -n "${TRAVIS}" ]; then
        DESTDIR="${HOME}/.bin"  # cached folder
    else
        DESTDIR="${BASEDIR}/.synapse"
        mkdir -p "${DESTDIR}"
    fi
fi

SYNAPSE="${DESTDIR}/synapse"
# build synapse single-file executable
if [ ! -x "${SYNAPSE}" ]; then
    if [ ! -d "${BUILDDIR}" ]; then
        BUILDDIR="$( mktemp -d )"
        RMBUILDDIR="1"
    fi
    pushd "${BUILDDIR}"

    virtualenv -p "$(which python2)" venv
    ./venv/bin/pip install "${SYNAPSE_URL}" pyinstaller
    SYNDIR="$( find venv/lib -name synapse -type d | head -1 )"
    ./venv/bin/pyinstaller -F -n synapse \
        --hidden-import="sqlite3" \
        --add-data="${SYNDIR}/storage/schema:synapse/storage/schema" \
        "${SYNDIR}/app/homeserver.py"
    cp -v dist/synapse "${SYNAPSE}"

    popd
    [ -n "${RMBUILDDIR}" ] && rm -r "${BUILDDIR}"
fi

cp ${BASEDIR}/raiden/tests/test_files/synapse-config.yaml ${DESTDIR}/synapse-config.yml
"${SYNAPSE}" --server-name="${SYNAPSE_SERVER_NAME}" \
           --config-path="${DESTDIR}/synapse-config.yml" \
           --generate-keys

if [ -z ${TRAVIS} ]; then
  LOG_FILE="${DESTDIR}/homeserver.log"
  CLEAR_LOG="[ -f ${LOG_FILE} ] && rm ${LOG_FILE}"
  LOGGING_OPTION="--log-file ${LOG_FILE}"
fi

cat > "${DESTDIR}/run_synapse.sh" << EOF
#!/bin/sh
SYNAPSEDIR=\$( dirname "\$0" )
${CLEAR_LOG}
exec "\${SYNAPSEDIR}/synapse" \
  --server-name="\${SYNAPSE_SERVER_NAME:-${SYNAPSE_SERVER_NAME}}" \
  --config-path="\${SYNAPSEDIR}/synapse-config.yml" \
  ${LOGGING_OPTION}
EOF
chmod 775 "${DESTDIR}/run_synapse.sh"
