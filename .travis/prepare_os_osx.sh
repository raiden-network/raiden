#!/usr/bin/env bash

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
  local timeout=20 # in minutes
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

for tool in automake libtool pkg-config libffi gmp openssl node ; do
    travis_wait brew install ${tool} || travis_wait brew upgrade ${tool}
done

curl -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py --user
