#!/usr/bin/env bash

set -e
set -x

fail() {
    if [[ $- == *i* ]]; then
       red=`tput setaf 1`
       reset=`tput sgr0`

       echo "${red}==> ${@}${reset}"
    fi
    exit 1
}

info() {
    if [[ $- == *i* ]]; then
        blue=`tput setaf 4`
        reset=`tput sgr0`

        echo "${blue}${@}${reset}"
    fi
}

success() {
    if [[ $- == *i* ]]; then
        green=`tput setaf 2`
        reset=`tput sgr0`
        echo "${green}${@}${reset}"
    fi

}

warn() {
    if [[ $- == *i* ]]; then
        yellow=`tput setaf 3`
        reset=`tput sgr0`

        echo "${yellow}${@}${reset}"
    fi
}

[ -z "${SOLC_VERSION}" ] && fail 'missing SOLC_VERSION'

# if [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
#     # SOLC_URL=${SOLC_URL_MACOS}
#     cp solc.txt $HOME/.bin/solc-${SOLC_VERSION}-${TRAVIS_OS_NAME}
# else
#     SOLC_URL=${SOLC_URL_LINUX}
# fi

[ -z "${SOLC_URL}" ] && fail 'missing SOLC_URL'

if [ ! -x $HOME/.bin/solc-${SOLC_VERSION}-${TRAVIS_OS_NAME} ]; then
    mkdir -p $HOME/.bin

    # use docker for macOS
    if [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
        cp solc.sh $HOME/.bin/solc-${SOLC_VERSION}-${TRAVIS_OS_NAME}
    else
        SOLC_URL=${SOLC_URL_LINUX}
        curl -L ${SOLC_URL} > $HOME/.bin/solc-${SOLC_VERSION}-${TRAVIS_OS_NAME}
    fi

    chmod 775 $HOME/.bin/solc-${SOLC_VERSION}-${TRAVIS_OS_NAME}
    success "solc ${SOLC_VERSION} installed"
else
    info 'using cached solc'
fi

# always recreate the symlink since we dont know if it's pointing to a different
# version
[ -h $HOME/.bin/solc ] && unlink $HOME/.bin/solc
ln -s $HOME/.bin/solc-${SOLC_VERSION}-${TRAVIS_OS_NAME} $HOME/.bin/solc
