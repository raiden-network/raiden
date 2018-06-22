#!/usr/bin/env bash

set -e
set -x

clone_repo() {
    git clone git@github.com:raiden-network/homebrew-raiden
    cd homebrew-raiden
}

setup_git() {
    openssl aes-256-cbc -K $encrypted_d89a2734327d_key -iv $encrypted_d89a2734327d_iv -in ../.travis/homebrew-raiden_github_deploy.enc -out ${HOME}/homebrew-raiden_github_deploy -d
    git config core.sshCommand "ssh -i ~/homebrew-raiden_github_deploy"
    git config user.email "contact@raiden.network"
    git config user.name "Raiden Network"
}

update_formula() {
    UPDATED_SHA256=$(openssl sha -sha256 dist/raiden-${TRAVIS_TAG}-macOS.zip)
    FORMULA_FILE="homebrew-raiden/raiden.rb"

    sed -i .bak "s/[0-9]\.[0-9]\.[0-9]/${TRAVIS_TAG/v/}/g" $FORMULA_FILE
    sed -i .bak "s/sha256 \"[a-f0-9]\{64\}\"/sha256 \"${UPDATED_SHA256: -64}\"/g" $FORMULA_FILE

    rm $FORMULA_FILE.bak
}

commit_formula_file() {
    git add raiden.rb
    git commit -m "Update formula to ${TRAVIS_TAG}"
    git tag -a "${TRAVIS_TAG}"
}

upload_file() {
    git push --tags
}

clone_repo
setup_git
update_formula
commit_formula_file
upload_file
