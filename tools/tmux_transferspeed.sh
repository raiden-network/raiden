#!/usr/bin/env bash

set -e

function waitfor() {
    while [[ ! -s $1 ]]; do sleep 1; done
}

function info() {
    # bold and blue
    printf "$(tput bold)$(tput setaf 4) -> $1$(tput sgr0)\n" >&1
}

function msg() {
    # bold and green
    printf "$(tput bold)$(tput setaf 2) $1$(tput sgr0)\n" >&1
}


error () {
    # bold and red
    printf "$(tput bold)$(tput setaf 1) ERROR: $1$(tput sgr0)\n" >&1
}

die() {
    error "$@"
    exit 1
}

function cleanup() {
    [ -n "${TEMP}" ] && rm -rf ${TEMP}
}

function followlog() {
    target=$1
    logfile=$2
    tmux split-window -v -t "${target}"
    tmux resize-pane -t "${target}" -y 10
    tmux send-keys -t "${target}" "sleep 10 && tail -f ${logfile}" C-m
}

TEMP=$(mktemp -d "/tmp/raiden.XXXXX")
touch $TEMP/password
GETHPORT=8101

SETUP_CHANNELS=1
SETUP_VARIABLES=1
SETUP_TMUX=1
PYFLAME_OUTPUT=""
GENESIS=$TEMP/genesis.json

while getopts "cvtg:p:h" arg; do
    case $arg in
        c)
            SETUP_CHANNELS=0
            ;;
        v)
            SETUP_VARIABLES=0
            ;;
        t)
            SETUP_TMUX=0
            ;;
        g)
            GENESIS=$OPTARG
            ;;
        p)
            PYFLAME_OUTPUT=$OPTARG
            ;;
        h)
            echo "Usage: $0 [-c -v -t -g genesis_file -p output.svg -h]"
            echo "  -c: disable channel setup"
            echo "  -v: disable variable definitions"
            echo "  -t: disable tmux windowing"
            echo "  -g genesis_file: use genesis file to initialize geth"
            echo "  -p output.svg: write pyflame results to output.svg"
            echo "  -h: show help"
            echo ""
            exit 0
            ;;
        \?)
            error "unknow arg $OPTARG"
            exit
            ;;
    esac
done

shift $((OPTIND-1))

INIT=$1

# the temp directory should be removed only after the tmux session is exited
# trap cleanup 1 2 3 9 15

# this will create 3 nodes with deterministic keys, deploy raiden's smart
# contract and create tokens for testing. The private keys are based on the ip
# address and an incrementing port number, for each account a token will be
# created and the distributed to _all_ the other participants. The genesis
# block can be reused between sessions to have faster startup times.
[ ! -e "${GENESIS}" ] && {
    info "generating the ${GENESIS}"
    python ./tools/config_builder.py full_genesis 3 127.0.0.1 > $GENESIS
}

# cached private keys and accounts (./tools/config_builder.py accounts 3 127.0.0.1)
PRIVKEY1=51c662cae295bdef5b0b895065aaa105089375e6541381dc17ba6d3ea0451052
PRIVKEY2=20d8b10d23ec1f00b54d798c9120fae94cff91e8db936affe6ef9d80a74c3535
PRIVKEY3=aa3e84aa62daa5186d75663ff09c62500b998fe143bdfbb1b7e29b8e5583970b

ADDRESS1=67febce7e8f81e6c6b6624a6cef64b4b717c0194
ADDRESS2=01551883681ba1eedf9403f743808776cc9e509a
ADDRESS3=397a25e3c9c66c870e2a044379da9429156aa05f

TOKEN1=$(jq -r ".config.token_groups[\"${ADDRESS1}\"]" $GENESIS)

LOG1=${TEMP}/node1
LOG2=${TEMP}/node2
LOG3=${TEMP}/node3

STAGE1_1=${LOG1}.stage1
STAGE1_2=${LOG2}.stage1
STAGE1_3=${LOG3}.stage1

STAGE2_1=${LOG1}.stage2
STAGE2_2=${LOG2}.stage2

RAIDEN_CONTRACTS=$(jq -r .config.raidenFlags $GENESIS)

RAIDEN_TEMPLATE="python raiden/app.py \
    --eth_rpc_endpoint 127.0.0.1:${GETHPORT} \
    --listen_address 0.0.0.0:%s \
    --privatekey=%s \
    $RAIDEN_CONTRACTS \
    --logging ':DEBUG' \
    --logfile %s"

RAIDEN_VARIABLE_TEMPLATE="
raiden1='${ADDRESS1}'
raiden2='${ADDRESS2}'
raiden3='${ADDRESS3}'
asset='${TOKEN1}'
am=raiden.get_manager_by_asset_address('${TOKEN1}'.decode('hex'))"

[ "$SETUP_TMUX" -eq 1 ] && {
    info "creating the tmux windows/panels"

    tmux new-session -d -s raiden

    tmux new-window -t raiden:2 -n geth
    tmux new-window -t raiden:3 -n client1
    tmux new-window -t raiden:4 -n client2
    tmux new-window -t raiden:5 -n client3
    tmux new-window -t raiden:6 -n pyflame

    tmux send-keys -t raiden:2 "$INIT" C-m
    tmux send-keys -t raiden:3 "$INIT" C-m
    tmux send-keys -t raiden:4 "$INIT" C-m
    tmux send-keys -t raiden:5 "$INIT" C-m
    tmux send-keys -t raiden:6 "$INIT" C-m

    tmux send-keys -t raiden:2 "geth --datadir ${TEMP} init ${GENESIS}" C-m
    tmux send-keys -t raiden:2 "geth --datadir ${TEMP} --password ${TEMP}/password account new" C-m
    tmux send-keys -t raiden:2 "geth --minerthreads 1 --nodiscover --rpc --rpcport ${GETHPORT} --mine --etherbase 0 --datadir ${TEMP}" C-m

    tmux send-keys -t raiden:3 "$(printf "$RAIDEN_TEMPLATE" 40001 "${PRIVKEY1}" "${LOG1}")" C-m
    tmux send-keys -t raiden:4 "$(printf "$RAIDEN_TEMPLATE" 40002 "${PRIVKEY2}" "${LOG2}")" C-m
    tmux send-keys -t raiden:5 "$(printf "$RAIDEN_TEMPLATE" 40003 "${PRIVKEY3}" "${LOG3}")" C-m

    followlog raiden:3 $LOG1
    followlog raiden:4 $LOG2
    followlog raiden:5 $LOG3

    tmux last-pane -t raiden:3
    tmux last-pane -t raiden:4
    tmux last-pane -t raiden:5
}

#[ "x$PYFLAME_OUTPUT" != "x" ] && {
#    tmux new-window -t raiden:6 -n pyflame
#    tmux send-keys -t raiden:6 "$INIT" C-m
#}

[ "$SETUP_CHANNELS" -eq 1 ] && {
    info "configuring the raiden channels"
    printf "      %64s %40s %s\n" PRIVKEY ADDRESS CHANNELS
    echo "node1 ${PRIVKEY1} ${ADDRESS1} asset with balance"
    echo "node2 ${PRIVKEY2} ${ADDRESS2} asset with balance"
    echo "node3 ${PRIVKEY3} ${ADDRESS3} asset with balance"

    # assume the genesis file already has distributed asset to all nodes

    tmux send-keys -t raiden:3 "import time; from os.path import isfile" C-m
    tmux send-keys -t raiden:4 "import time; from os.path import isfile" C-m
    tmux send-keys -t raiden:5 "import time; from os.path import isfile" C-m

    tmux send-keys -t raiden:3 "tools.register_asset('${TOKEN1}'); open('${STAGE1_1}', 'w').close()" C-m
    tmux send-keys -t raiden:4 "tools.register_asset('${TOKEN1}'); open('${STAGE1_2}', 'w').close()" C-m
    tmux send-keys -t raiden:5 "tools.register_asset('${TOKEN1}'); open('${STAGE1_3}', 'w').close()" C-m

    # wait for assets to be registered
    tmux send-keys -t raiden:3 "while not all([isfile('${STAGE1_1}'), isfile('${STAGE1_2}'), isfile('${STAGE1_3}')]): time.sleep(.1)" C-m
    tmux send-keys -t raiden:4 "while not all([isfile('${STAGE1_1}'), isfile('${STAGE1_2}'), isfile('${STAGE1_3}')]): time.sleep(.1)" C-m
    tmux send-keys -t raiden:5 "while not all([isfile('${STAGE1_1}'), isfile('${STAGE1_2}'), isfile('${STAGE1_3}')]): time.sleep(.1)" C-m

    tmux send-keys -t raiden:3 "tools.open_channel_with_funding('${TOKEN1}', '${ADDRESS2}', 1000); open('${STAGE2_1}', 'w').close()" C-m
    tmux send-keys -t raiden:4 "tools.open_channel_with_funding('${TOKEN1}', '${ADDRESS3}', 1000); open('${STAGE2_2}', 'w').close()" C-m
}

[ "$SETUP_VARIABLES" -eq 1 ] && {
    tmux send-keys -t raiden:3 "${RAIDEN_VARIABLE_TEMPLATE}" C-m
    tmux send-keys -t raiden:4 "${RAIDEN_VARIABLE_TEMPLATE}" C-m
    tmux send-keys -t raiden:5 "${RAIDEN_VARIABLE_TEMPLATE}" C-m

    # wait for all channels to be open
    tmux send-keys -t raiden:3 "while not all([isfile('${STAGE2_1}'), isfile('${STAGE2_2}')]): time.sleep(.1)" C-m
    tmux send-keys -t raiden:4 "while not all([isfile('${STAGE2_1}'), isfile('${STAGE2_2}')]): time.sleep(.1)" C-m
    tmux send-keys -t raiden:5 "while not all([isfile('${STAGE2_1}'), isfile('${STAGE2_2}')]): time.sleep(.1)" C-m

    # do 100 transfers
    tmux send-keys -t raiden:3 "for _ in range(100): raiden.api.transfer_and_wait('${TOKEN1}'.decode('hex'), 1, '${ADDRESS3}'.decode('hex'))" C-m
}

[ "x$PYFLAME_OUTPUT" != "x" ] && {
    # wait for open channels
    tmux send-keys -t raiden:6 "while [[ ! -f ${STAGE2_1} ]]; do sleep 0.1; done" C-m

    tmux send-keys -t raiden:6 "pyflame -x -s 60 `pgrep -a python | grep 40001 | cut -d' ' -f1` | flamegraph.pl > ${PYFLAME_OUTPUT}" C-m
}

echo
echo 'tmux sesion created, attach to it using the following command:'
echo
msg "tmux attach-session -t raiden && rm -rf ${TEMP}"
echo
