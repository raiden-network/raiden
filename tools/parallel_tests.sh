#!/usr/bin/bash

set -e
trap 'kill $(jobs -p)' EXIT

tmpdir=$(mktemp -d)
alltest=${tmpdir}/all_test
output=${tmpdir}/sessions
logs=${tmpdir}/logs
parallelism=${PARALLELISM:-4}
session_prefixes="${output}/raiden-tests"

echo 'Tests files located at'
echo ${tmpdir}

mkdir -p ${output} ${logs}

pytest --quiet --collect-only $@ | grep :: > ${alltest}
split --number "l/${parallelism}" --numeric-suffixes ${alltest} ${session_prefixes}

for f in ${session_prefixes}*; do
    logfile=$(basename ${f})
    pytest --select-from-file ${f} > ${logs}/${logfile} &
done

wait  # wait for all tests to run

exit $?
