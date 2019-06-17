#!/usr/bin/env bash

set -o errexit
set -o xtrace
set -o nounset

access_key=$1
secret_key=$2
dir=$3
bucket=$4
endpoint=$5

s3cmd \
    --access_key ${access_key} \
    --secret_key ${secret_key} \
    --host ${endpoint} \
    --host-bucket "%(bucket)s.${endpoint}" \
    --no-progress \
    --stats \
    --no-delete-removed \
    --guess-mime-type \
    --acl-public \
    put \
    ${dir}/_LATEST*.txt \
    s3://${bucket}/

s3cmd \
    --access_key ${access_key} \
    --secret_key ${secret_key} \
    --host ${endpoint} \
    --host-bucket "%(bucket)s.${endpoint}" \
    --no-progress \
    --stats \
    --no-delete-removed \
    --guess-mime-type \
    --acl-public \
    put \
    ${dir}/raiden* \
    s3://${bucket}/${RELEASE_TYPE}/