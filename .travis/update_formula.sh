#!/usr/bin/env bash

set -e
set -x

clone_repo() {
    git clone https://github.com/raiden-network/homebrew-raiden
}

update_formula() {
    UPDATED_SHA256=$(openssl sha -sha256 ./dist/raiden-${TRAVIS_TAG}-macOS.zip)
    FORMULA_FILE="./homebrew-raiden/raiden.rb"

    sed -i .bak "s/[0-9]\.[0-9]\.[0-9]/${TRAVIS_TAG/v/}/g" $FORMULA_FILE
    sed -i .bak "s/sha256 \"[a-f0-9]{64}\"/sha256 \"${UPDATED_SHA256: -64}\"/g" $FORMULA_FILE

    rm $FORMULA_FILE.bak
}

setup_git() {
    git config --global user.email "travis@travis-ci.org"
    git config --global user.name "Travis CI"
}

commit_formula_file() {
    cd ./homebrew-raiden
    git checkout -b release-${TRAVIS_TAG}
    git add raiden.rb
    git commit -m "Update formula to ${TRAVIS_TAG}"
}

upload_file() {
    git remote add release-${TRAVIS_TAG} https://${GH_TOKEN}@github.com/raiden-network/homebrew-raiden.git > /dev/null 2>&1
    git push --quiet --set-upstream release-${TRAVIS_TAG} master
}

clone_repo
update_formula
setup_git
commit_formula_file
upload_file
