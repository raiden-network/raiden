#!/usr/bin/env sh

######################################################
### Run coverage, generate and display html report ###
######################################################
###
### Configurable through environment variables.
###
### Examples:
##############
##
## Run complete SUITE, generate coverage report for all and open overview page in browser
#
# test_and_report.sh
#
## Run complete SUITE, generate report for only node.py and open report for node.py in browser
#
# ONLY=raiden/transfer/node.py test_and_report.sh
#
## Same as above but more verbose (SHOW is configured implicitly above)
#
# ONLY=raiden/transfer/node.py SHOW=raiden_transfer_node_py.html test_and_report.sh
#
## Run pytest with `-s --pdb` flags
#
# PYTEST="$(which pytest) -s --pdb" test_and_report.sh
#
## Don't display in browser, but show path to file
#
# OPEN=echo test_and_report.sh
#
## Only run a specific test
#
# SUITE=raiden/tests/unit/transfer/test_node.py test_and_report.sh
#

## configurable values
# pytest executable
PYTEST=${PYTEST:-$(which pytest)}
# specify non temp output directory
OUT_DIR=${OUT_DIR:-$(mktemp -d)}
# which tests to execute
SUITE=${SUITE:-raiden/tests/unit raiden/tests/fuzz}
# report only these files
ONLY=${ONLY:-*}
# open specific file
SHOW=${SHOW:-index.html}

# how to display html
if [[ "$(python -c 'import sys; print(sys.platform.lower())')" = "darwin" ]]
then
    if [[ -z ${OPEN} ]]
    then
        OPEN=open
    fi
fi

OPEN=${OPEN:-xdg-open}

# be a bit smarter about which file to display
if [[ "$ONLY" = "*" ]];
then
    SHOW=${SHOW:-index.html}
else
    SHOW=$(python -c "import sys; print(sys.argv[1].replace('/', '_').replace('.', '_') + '.html')" $ONLY)
fi

# in case that out dir was configured, make sure, that it exists
mkdir -p $OUT_DIR

rm .coverage
coverage run --branch $PYTEST -x $SUITE && coverage html -d $OUT_DIR --include=$ONLY && $OPEN $OUT_DIR/$SHOW
