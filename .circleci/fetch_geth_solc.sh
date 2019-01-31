#!/usr/bin/env bash

set -e
set -x

GETH_PATH="${HOME}/.local/bin/geth-${OS_NAME}-${GETH_VERSION}"
if [[ ! -x ${GETH_PATH} ]]; then
  mkdir -p ${HOME}/.local/bin
  TEMP=$(mktemp -d 2>/dev/null || mktemp -d -t 'gethtmp')
  pushd ${TEMP}
  GETH_URL_VAR="GETH_URL_${OS_NAME}"
  wget -O geth.tar.gz ${!GETH_URL_VAR}
  tar xzf geth.tar.gz
  cd geth*/
  install -m 755 geth ${GETH_PATH}
fi
ln -sf ${GETH_PATH} ${HOME}/.local/bin/geth

SOLC_PATH="${HOME}/.local/bin/solc-${OS_NAME}-${SOLC_VERSION}"
if [[ ! -x ${SOLC_PATH} ]]; then
  mkdir -p ${HOME}/.local/bin
  SOLC_URL_VAR="SOLC_URL_${OS_NAME}"
  curl -L ${!SOLC_URL_VAR} > ${SOLC_PATH}
  chmod 775 ${SOLC_PATH}
fi
ln -sf ${SOLC_PATH} ${HOME}/.local/bin/solc
