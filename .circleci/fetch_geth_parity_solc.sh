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

  GETH_MD5_VAR="GETH_MD5_${OS_NAME}"
  if [[ ! -n ${!GETH_MD5_VAR} ]]; then
      COMPUTED_MD5=$(md5sum ${GETH_PATH} | cut '-d ' -f1)

      if [[ ${COMPUTED_MD5} != ${!GETH_MD5_VAR} ]]; then
          exit 1;
      fi
  fi
fi
ln -sfn ${GETH_PATH} ${LOCAL_BASE}/bin/geth

PARITY_PATH="${LOCAL_BASE}/bin/parity-${OS_NAME}-${PARITY_VERSION}"
if [[ ! -x ${PARITY_PATH} ]]; then
  mkdir -p ${LOCAL_BASE}/bin
  PARITY_URL_VAR="PARITY_URL_${OS_NAME}"
  curl -L ${!PARITY_URL_VAR} > ${PARITY_PATH}
  chmod 775 ${PARITY_PATH}

  PARITY_SHA256_VAR="PARITY_SHA256_${OS_NAME}"
  if [[ ! -n ${!PARITY_SHA256_VAR} ]]; then
      COMPUTED_SHA256=$(sha256sum ${PARITY_PATH} | cut '-d ' -f1)

      if [[ ${COMPUTED_SHA256} != ${!PARITY_SHA256_VAR} ]]; then
          exit 1;
      fi
  fi
fi
ln -sfn ${PARITY_PATH} ${LOCAL_BASE}/bin/parity

# Only deal with solc for Linux since it's only used for testing
if [[ ${OS_NAME} != "LINUX" ]]; then
    exit 0
fi

SOLC_PATH="${LOCAL_BASE}/bin/solc-${OS_NAME}-${SOLC_VERSION}"
if [[ ! -x ${SOLC_PATH} ]]; then
  mkdir -p ${LOCAL_BASE}/bin
  SOLC_URL_VAR="SOLC_URL_${OS_NAME}"
  curl -L ${!SOLC_URL_VAR} > ${SOLC_PATH}
  chmod 775 ${SOLC_PATH}
fi
ln -sfn ${SOLC_PATH} ${LOCAL_BASE}/bin/solc
