set -ex

#!/bin/bash
if [[ ! -z ${TRAVIS_TAG} ]]; then
    export ARCHIVE_TAG=${TRAVIS_TAG}
else
    DATE=$(date +%Y-%m-%dT%H-%M-%S)
    RAIDEN_VERSION=$(python setup.py --version)
    export ARCHIVE_TAG="nightly-${DATE}-v${RAIDEN_VERSION}"
fi

set +ex
