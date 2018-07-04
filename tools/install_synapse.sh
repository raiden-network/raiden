#!/usr/bin/env bash

set -exo pipefail

PYTHON2_VERSION=$(python2 -c 'import sys; print ".".join(str(v) for v in sys.version_info[:2])' || true)

if [[ ${PYTHON2_VERSION} != "2.7" ]]; then
    echo This script requires Python 2.7
    exit 1
fi

SYNAPSE_URL="${SYNAPSE_URL:-https://github.com/matrix-org/synapse/tarball/master#egg=matrix-synapse}"
SYNAPSE_SERVER_NAME="${SYNAPSE_SERVER_NAME:-matrix.local.raiden}"
BASEDIR=$(python3 -c 'import sys; from pathlib import Path; print(Path(sys.argv[1]).parent.parent.absolute())' "$0")

if [[ ! -d ${DESTDIR} ]]; then
    if [[ -n ${TRAVIS} ]]; then
        DESTDIR="${HOME}/.bin"  # cached folder
    else
        DESTDIR="${BASEDIR}/.synapse"
        mkdir -p "${DESTDIR}"
    fi
fi

# versioned binary according to this script's last commit
SYNAPSE="${DESTDIR}/synapse.$( git log -n1 --pretty=format:%h -- ${0} )"
SYNAPSE_LINK="${DESTDIR}/synapse"
# build synapse single-file executable
# if file not exist or this script is newer than it
if [[ ! -x ${SYNAPSE} ]]; then
    if [[ ! -d ${BUILDDIR} ]]; then
        BUILDDIR="$( mktemp -d )"
        RMBUILDDIR="1"
    fi
    pushd "${BUILDDIR}"

    virtualenv -p "$(which python2)" venv
    ./venv/bin/pip install "${SYNAPSE_URL}" pyinstaller
    SYNDIR="$( find venv/lib -name synapse -type d | head -1 )"
    ./venv/bin/pyinstaller -F -n synapse \
        --hidden-import="sqlite3" \
        --hidden-import="syweb" \
        --add-data="${SYNDIR}/storage/schema:synapse/storage/schema" \
        --add-data="${SYNDIR}/../syweb:syweb" \
        "${SYNDIR}/app/homeserver.py"
    rm -f ${DESTDIR}/synapse.*
    cp dist/synapse "${SYNAPSE}"

    popd
    [[ -n ${RMBUILDDIR} ]] && rm -r "${BUILDDIR}"
fi

ln -fs "${SYNAPSE}" "${SYNAPSE_LINK}"
cp "${BASEDIR}/raiden/tests/test_files/synapse-config.yaml" "${DESTDIR}/"
"${SYNAPSE}" --server-name="${SYNAPSE_SERVER_NAME}" \
           --config-path="${DESTDIR}/synapse-config.yaml" \
           --generate-keys

cat > "${DESTDIR}/run_synapse.sh" << EOF
#!/usr/bin/env bash
SYNAPSEDIR=\$( dirname "\$0" )
LOG_FILE="\${SYNAPSEDIR}/homeserver.log"
[[ -f \${LOG_FILE} ]] && rm "\${LOG_FILE}"
LOGGING_OPTION="--log-file \${LOG_FILE}"
exec "\${SYNAPSEDIR}/synapse" \
  --server-name="\${SYNAPSE_SERVER_NAME:-${SYNAPSE_SERVER_NAME}}" \
  --config-path="\${SYNAPSEDIR}/synapse-config.yaml" \
  \${LOGGING_OPTION} \$@
EOF
chmod 775 "${DESTDIR}/run_synapse.sh"
