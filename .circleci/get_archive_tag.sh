#!/bin/bash
set -ex

if [[ ! -z ${CIRCLE_TAG} ]]; then
    export ARCHIVE_TAG=${CIRCLE_TAG}
else
    DATE=$(date +%Y-%m-%dT%H-%M-%S)
    RAIDEN_VERSION=$(python setup.py --version)
    export ARCHIVE_TAG="nightly-${DATE}-v${RAIDEN_VERSION}"
fi

echo "export ARCHIVE_TAG=${ARCHIVE_TAG}" >> ${BASH_ENV}

set +ex
