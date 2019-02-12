#!/usr/bin/env bash

set -e
set -x

if [[ -z ${LOCAL_BASE} ]]; then
    LOCAL_BASE=~/.local
fi

GETH_PATH="${LOCAL_BASE}/bin/geth-${OS_NAME}-${GETH_VERSION}"
if [[ ! -x ${GETH_PATH} ]]; then
  mkdir -p ${LOCAL_BASE}/bin
  TEMP=$(mktemp -d 2>/dev/null || mktemp -d -t 'gethtmp')
  pushd ${TEMP}
  GETH_URL_VAR="GETH_URL_${OS_NAME}"
  curl -o geth.tar.gz ${!GETH_URL_VAR}
  tar xzf geth.tar.gz
  cd geth*/
  install -m 755 geth ${GETH_PATH}
fi
ln -sf ${GETH_PATH} ${LOCAL_BASE}/bin/geth

PARITY_PATH="${LOCAL_BASE}/bin/parity-${OS_NAME}-${PARITY_VERSION}"
if [[ ! -x ${PARITY_PATH} ]]; then
  mkdir -p ${LOCAL_BASE}/bin
  PARITY_URL_VAR="PARITY_URL_${OS_NAME}"
  curl -L ${!PARITY_URL_VAR} > ${PARITY_PATH}
  chmod 775 ${PARITY_PATH}
fi
ln -sf ${PARITY_PATH} ${LOCAL_BASE}/bin/parity

SOLC_PATH="${LOCAL_BASE}/bin/solc-${OS_NAME}-${SOLC_VERSION}"
if [[ ! -x ${SOLC_PATH} ]]; then
  mkdir -p ${LOCAL_BASE}/bin
  SOLC_URL_VAR="SOLC_URL_${OS_NAME}"
  curl -L ${!SOLC_URL_VAR} > ${SOLC_PATH}
  chmod 775 ${SOLC_PATH}
fi
ln -sf ${SOLC_PATH} ${LOCAL_BASE}/bin/solc
