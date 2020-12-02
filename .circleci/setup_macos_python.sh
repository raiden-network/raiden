#!/usr/bin/env bash

set -e
set -x

[[ -n ${OS_NAME:?} ]]
[[ -n ${PYTHON_VERSION_SHORT:?} ]]
[[ -n ${PY_PATH_HOMEBREW:?} ]]

# Only deal with solc for Linux since it's only used for testing
if [[ ${OS_NAME} != "MACOS" ]]; then
    exit 0
fi


if [[ ${PYTHON_VERSION_SHORT} != "3.7" ]] && [[ ${PYTHON_VERSION_SHORT} != "3.8" ]]; then
  # not supported by MacOS
  exit 1
fi
if [[ ! -x ${PY_PATH_HOMEBREW} ]]; then
  # install Python via Homebrew
  # (Only Minor version specifier supported, will pull most
  # recent stable release)
  brew install python@"${PYTHON_VERSION_SHORT}"
  # TODO do we also need some version checksums etc here?
fi
