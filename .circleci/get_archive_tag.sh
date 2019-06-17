#!/bin/bash
set -ex

if [[ ! -z ${CIRCLE_TAG} ]]; then
    export ARCHIVE_TAG=${CIRCLE_TAG}
    if [[ ${CIRCLE_TAG} = "*-rc*" ]]; then
        export RELEASE_TYPE="RC"
    else
        export RELEASE_TYPE="RELEASE"
    fi

else
    DATE=$(date +%Y-%m-%dT%H-%M-%S)
    RAIDEN_VERSION=$(python setup.py --version)
    export ARCHIVE_TAG="nightly-${DATE}-v${RAIDEN_VERSION}"
    export RELEASE_TYPE="NIGHTLY"
fi

echo "export ARCHIVE_TAG=${ARCHIVE_TAG}" >> ${BASH_ENV}
echo "export RELEASE_TYPE=${RELEASE_TYPE}" >> ${BASH_ENV}

set +ex
