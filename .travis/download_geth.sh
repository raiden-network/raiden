#!/usr/bin/env bash

set -e

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

[ -z "${GETH_URL}" ] && fail 'missing GETH_URL'
[ -z "${GETH_VERSION}" ] && fail 'missing GETH_VERSION'

if [ ! -x $HOME/.bin/geth-${GETH_VERSION} ]; then
    mkdir -p $HOME/.bin

    TEMP=$(mktemp -d)
    cd $TEMP
    wget -O geth.tar.gz $GETH_URL
    tar xzf geth.tar.gz

    cd geth*/
    install -m 755 geth $HOME/.bin/geth-${GETH_VERSION}

    success "geth ${GETH_VERSION} installed"
else
    info 'using cached geth'
fi

# always recreate the symlink since we dont know if it's pointing to a different
# version
[ -h $HOME/.bin/geth ] && unlink $HOME/.bin/geth
ln -s $HOME/.bin/geth-${GETH_VERSION} $HOME/.bin/geth
