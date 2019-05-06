#!/bin/bash

# This checks that no dependency is pinned more then once. This will break the
# build for easy to miss erros, e.g. upgrading a dependency in the requirements
# file without realizing it is also in constraints, which will not change the
# used version for `pip -r -c` installs but it will change it release installs.

# This script assumes that all `requirements` files have pinned versions, and
# that `constraints` files are only used to pin downstream dependencies for
# deterministic builds.

set -e
# set -x

function die() {
    msg=$1
    echo $msg
    exit 1
}

function clean_and_sort(){
    file=$1
    out=$2
    tmp=$(mktemp)

    # remove:
    # - empty lines
    # - require expressions `-r <file>`
    # - constraints expressions `-c <file>`
    # - comments `# blah blah`
    egrep --invert-match \
        --regexp='^[[:space:]]*$' \
        --regexp='^[[:space:]]*-r[[:space:]]' \
        --regexp='^[[:space:]]*-c[[:space:]]' \
        --regexp='^[[:space:]]*#' \
        "${file}" > "${tmp}"

    # remove verison pinning
    sed 's/==[[:space:]]*[0-9.]+[[:space:]]*$//' "${tmp}" > "${out}"
}

function forbid_repeated_lines() {
    # To use this function the files must have been cleaned. Both by removing
    # empty lines and cleaning version pinning (e.g. `==1.0.1`)
    file1=$1

    total_lines=$(cat "${file1}" | wc --lines)
    unique_lines=$(uniq "${file1}" | wc --lines)

    if [[ ${total_lines} != ${unique_lines} ]]; then
        uniq --repeated $file1
        return 1
    fi
}

function sponge() {
    out="${1}"
    tmp=$(mktemp)
    cat - > "${tmp}"
    mv "${tmp}" "${out}"
}

function merge_sorted_into() {
    from_file=$1
    to_file=$2

    cat "${from_file}" "${to_file}" | sort | sponge "${to_file}"
}

requirements=$(mktemp)
requirements_dev=$(mktemp)
requirements_lint=$(mktemp)
requirements_docs=$(mktemp)
constraints=$(mktemp)
constraints_dev=$(mktemp)
all_dependencies=$(mktemp)

clean_and_sort requirements.txt "${requirements}"
clean_and_sort requirements-dev.txt "${requirements_dev}"
clean_and_sort requirements-lint.txt "${requirements_lint}"
clean_and_sort requirements-docs.txt "${requirements_docs}"

clean_and_sort constraints.txt "${constraints}"
clean_and_sort constraints-dev.txt "${constraints_dev}"

# first forbid repeated lines in the same file
forbid_repeated_lines "${requirements}" || die "requirements.txt has duplicated lines"
forbid_repeated_lines "${requirements_dev}" || die "requirements_dev.txt has duplicated lines"
forbid_repeated_lines "${requirements_lint}" || die "requirements_lint.txt has duplicated lines"
forbid_repeated_lines "${requirements_docs}" || die "requirements_docs.txt has duplicated lines"

forbid_repeated_lines "${constraints}" || die "constraints.txt has duplicated lines"
forbid_repeated_lines "${constraints_dev}" || die "constraints_dev.txt has duplicated lines"

# then check across dependency files
merge_sorted_into "${requirements}" "${all_dependencies}"
merge_sorted_into "${requirements_dev}" "${all_dependencies}"
forbid_repeated_lines "${all_dependencies}" || die "requirements_dev.txt has duplicated dependencies"

merge_sorted_into "${requirements_lint}" "${all_dependencies}"
forbid_repeated_lines "${all_dependencies}" || die "requirements_lint.txt has duplicated dependencies"

merge_sorted_into "${requirements_docs}" "${all_dependencies}"
forbid_repeated_lines "${all_dependencies}" || die "requirements_docs has duplicated dependencies"

merge_sorted_into "${constraints}" "${all_dependencies}"
forbid_repeated_lines "${all_dependencies}" || die "constraints has duplicated dependencies"

merge_sorted_into "${constraints_dev}" "${all_dependencies}"
forbid_repeated_lines "${all_dependencies}" || die "constraints_dev has duplicated dependencies"
