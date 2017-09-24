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

travis_wait() {
  local cmd="$@"
  local log_file=travis_wait_$$.log

  $cmd 2>&1 >$log_file &
  local cmd_pid=$!

  travis_jigger $! $cmd &
  local jigger_pid=$!
  local result

  {
    wait $cmd_pid 2>/dev/null
    result=$?
    ps -p$jigger_pid 2>&1>/dev/null && kill $jigger_pid
  } || exit 1

  exit $result
}

travis_jigger() {
  # helper method for travis_wait()
  local timeout=80 # in minutes
  local count=0

  local cmd_pid=$1
  shift

  while [ $count -lt $timeout ]; do
    count=$(($count + 1))
    echo -ne "Still running ($count of $timeout): $@\r"
    sleep 60
  done

  echo -e "\n\033[31;1mTimeout reached. Terminating $@\033[0m\n"
  kill -9 $cmd_pid
}


[ -z "${SOLC_URL_MACOS}" ] && fail 'missing SOLC_URL_MACOS'
[ -z "${SOLC_VERSION}" ] && fail 'missing SOLC_VERSION'

SOLC_CACHE_PATH=$HOME/.bin/solc-macos-${SOLC_VERSION}
SOLC_PATH=/usr/local/Cellar/solidity/${SOLC_VERSION/v/}/bin/solc

if [ ! -x ${SOLC_CACHE_PATH} ]; then
    travis_wait brew install ${SOLC_URL_MACOS}
    cp ${SOLC_PATH} ${SOLC_CACHE_PATH}
    success "solc ${SOLC_VERSION} installed"
else
    ln -sf ${SOLC_CACHE_PATH} $HOME/.bin/solc
    info 'using cached solc'
fi
