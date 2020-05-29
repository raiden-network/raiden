#!/bin/bash

# Upload flagged coverage reports. Mocked tests are grouped under
# integration tests and fuzz tests under unit tests.

FLAG=$1
if [[ "${FLAG}" == "mocked" ]]
  then FLAG=integration
elif [[ "${FLAG}" == "fuzz" ]]
  then FLAG=unit
fi

bash <(curl -s https://codecov.io/bash) -c -F $FLAG

