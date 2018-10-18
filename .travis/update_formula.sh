#!/usr/bin/env bash

set -ex

setup_git() {
    openssl aes-256-cbc -K ${encrypted_d89a2734327d_key} -iv ${encrypted_d89a2734327d_iv} -in .travis/homebrew-raiden_github_deploy.enc -out ${HOME}/homebrew-raiden_github_deploy -d
    # Make ssh happy
    chmod 600 ${HOME}/homebrew-raiden_github_deploy
    # Configure SSH key and disable host key checking to avoid hanging at the prompt
    git config --global core.sshCommand "ssh -i ~/homebrew-raiden_github_deploy -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
    git config --global user.email "contact@raiden.network"
    git config --global user.name "Raiden Network"
}

clone_repo() {
    git clone git@github.com:raiden-network/homebrew-raiden
}

update_formula() {
    UPDATED_SHA256=$(openssl dgst -sha256 dist/archive/raiden-${TRAVIS_TAG}-macOS.zip)
    FORMULA_FILE="homebrew-raiden/raiden.rb"

    sed -i .bak -E "s/[0-9]+\.[0-9]+\.[0-9]+/${TRAVIS_TAG/v/}/g" $FORMULA_FILE
    sed -i .bak -E "s/sha256 \"[a-f0-9]\{64\}\"/sha256 \"${UPDATED_SHA256: -64}\"/g" $FORMULA_FILE

    rm $FORMULA_FILE.bak
}

commit_formula_file() {
    pushd homebrew-raiden
    git add raiden.rb
    git commit -m "Update formula to ${TRAVIS_TAG}"
    git tag -a "${TRAVIS_TAG}" -m "${TRAVIS_TAG}"
    popd
}

upload_file() {
    pushd homebrew-raiden
    git push --follow-tags
    popd
}

setup_git
clone_repo
update_formula
commit_formula_file
upload_file
