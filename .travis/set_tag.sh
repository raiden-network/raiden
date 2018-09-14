set -ex

#!/bin/bash
if [[ ! -z ${TRAVIS_TAG} ]]; then
    export ARCHIVE_TAG=${TRAVIS_TAG}
else
    DATE=$(date +%Y-%m-%dT%H-%M-%S) && export ARCHIVE_TAG="nightly-$DATE"
fi

set +ex
