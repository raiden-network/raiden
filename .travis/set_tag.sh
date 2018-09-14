#!/bin/bash

if [[ ! -z ${TRAVIS_TAG} ]]; then
    export ARCHIVE_TAG=${TRAVIS_TAG}
else
    DATE=$(date +%Y-%m-%dT%T) && export ARCHIVE_TAG="nightly-$DATE"
fi
