#!/usr/bin/env bash

set -o errexit
set -o pipefail

tests=$1
blockchain_type=$2
additional_args=$3
output_file=$(mktemp)

{
    pytest \
        "${tests}" \
        --collect-only \
        --quiet \
        "--blockchain-type=${blockchain_type}" \
        ${additional_args} > ${output_file}
} || {
    # Print pytest's output if test selection failed. This may happen if a
    # depencency is broken or if the codebase has syntax errors.
    cat ${output_file};
    exit 1;
}

# Save the tests in a file, it will be used by follow up steps
cat ${output_file} \
    | grep '::' \
    | circleci tests split --split-by=timings --timings-type=testname \
    | grep '::' > selected-tests.txt

# Print all the selected tests for debugging
cat selected-tests.txt
