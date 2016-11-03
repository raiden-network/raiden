#!/bin/sh

set -e

fail() {
    red=`tput setaf 1`
    reset=`tput sgr0`

    echo "${red}==> ${@}${reset}"

    exit 1
}

info() {
    blue=`tput setaf 4`
    reset=`tput sgr0`

    echo "${blue}${@}${reset}"
}

success() {
    green=`tput setaf 2`
    reset=`tput sgr0`

    echo "${green}${@}${reset}"
}

warn() {
    yellow=`tput setaf 3`
    reset=`tput sgr0`

    echo "${yellow}${@}${reset}"
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

    if [ -e $HOME/.bin/geth ]; then
        warn "force removing $HOME/.bin/geth"
        rm -f $HOME/.bin/geth
    fi

    ln -s $HOME/.bin/geth-${GETH_VERSION} $HOME/.bin/geth

    success "geth ${GETH_VERSION} installed"
else
    info 'using cached geth'
fi
