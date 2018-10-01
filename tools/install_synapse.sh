#!/usr/bin/env bash

set -exo pipefail

PYTHON2_VERSION=$(python2 -c 'import sys; print ".".join(str(v) for v in sys.version_info[:2])' || true)

if [[ ${PYTHON2_VERSION} != "2.7" ]]; then
    echo This script requires Python 2.7
    exit 1
fi

SYNAPSE_URL="${SYNAPSE_URL:-https://github.com/matrix-org/synapse/archive/v0.33.6.tar.gz#egg=matrix-synapse}"
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
    ./venv/bin/pip install --upgrade pip pyinstaller
    ./venv/bin/pip install pysaml2==4.6.2 dis3 coincurve pycryptodome
    ./venv/bin/pip install "${SYNAPSE_URL}"
    SITE="$( ./venv/bin/python -c 'from distutils.sysconfig import get_python_lib; print(get_python_lib())' )"
    cp "${BASEDIR}/tools/eth_auth_provider.py2" "${SITE}/eth_auth_provider.py"
    ./venv/bin/pyinstaller -F -n synapse \
        --hidden-import="sqlite3" \
        --hidden-import="syweb" \
        --hidden-import="eth_auth_provider" \
        --hidden-import="saml2" \
        --add-data="${SITE}/synapse/storage/schema:synapse/storage/schema" \
        --add-data="${SITE}/syweb:syweb" \
        --add-data="${SITE}/Crypto/__init__.py:Crypto/" \
        --add-data="${SITE}/Crypto/Util:Crypto/Util" \
        --add-data="${SITE}/Crypto/Hash:Crypto/Hash" \
        --add-data="${SITE}/pysaml2-4.6.2.dist-info:pysaml2-4.6.2.dist-info" \
        "${SITE}/synapse/app/homeserver.py"
    rm -f ${DESTDIR}/synapse.*
    cp dist/synapse "${SYNAPSE}"

    popd
    [[ -n ${RMBUILDDIR} ]] && rm -r "${BUILDDIR}"
fi

ln -fs "${SYNAPSE}" "${SYNAPSE_LINK}"
cp "${BASEDIR}/tools/synapse-config.yaml" "${DESTDIR}/"
"${SYNAPSE}" --server-name="${SYNAPSE_SERVER_NAME}" \
           --config-path="${DESTDIR}/synapse-config.yaml" \
           --generate-keys

cat > "${DESTDIR}/run_synapse.sh" << EOF
#!/usr/bin/env bash
SYNAPSEDIR=\$( dirname "\$0" )
# redirect synapse stderr logs to stdout
if [[ -n "\${STDOUT_SYNAPSE}" ]]; then
  exec 2>&1
else
  mv -vf \${SYNAPSEDIR}/homeserver.log{,.1}
  exec &> \${SYNAPSEDIR}/homeserver.log
fi
exec "\${SYNAPSEDIR}/synapse" \
  --server-name="\${SYNAPSE_SERVER_NAME:-${SYNAPSE_SERVER_NAME}}" \
  --config-path="\${SYNAPSEDIR}/synapse-config.yaml" \$@
EOF
chmod 755 "${DESTDIR}/run_synapse.sh"
