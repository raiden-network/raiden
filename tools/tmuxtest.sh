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
    tmux send-keys -t "${target}" "touch ${logfile} && tail -f ${logfile}" C-m
}

TEMP=$(mktemp -d "/tmp/raiden.XXXXX")
touch $TEMP/password
GETHPORT=8101

SETUP_CHANNELS=1
SETUP_VARIABLES=1
SETUP_TMUX=1
GENESIS=$TEMP/genesis.json

while getopts "cvtg:" arg; do
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
        \?)
            error "unknow arg $OPTARG"
            exit
            ;;
    esac
done

shift $((OPTIND-1))

INIT=$1

# the temp directory should be remove only after the tmux session is exited
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
TOKEN2=$(jq -r ".config.token_groups[\"${ADDRESS2}\"]" $GENESIS)
TOKEN3=$(jq -r ".config.token_groups[\"${ADDRESS3}\"]" $GENESIS)

mkdir -p ${TEMP}/node{1..3}/keystore

KEYSTORE1=${TEMP}/node1/keystore
KEYSTORE2=${TEMP}/node2/keystore
KEYSTORE3=${TEMP}/node3/keystore

tools/config_builder.py private_to_account $PRIVKEY1 nopassword > ${KEYSTORE1}/raidenaccount.json
tools/config_builder.py private_to_account $PRIVKEY2 nopassword > ${KEYSTORE2}/raidenaccount.json
tools/config_builder.py private_to_account $PRIVKEY3 nopassword > ${KEYSTORE3}/raidenaccount.json

LOG1=${TEMP}/node1/raiden.log
LOG2=${TEMP}/node2/raiden.log
LOG3=${TEMP}/node3/raiden.log

RAIDEN_CONTRACTS=$(jq -r .config.raidenFlags $GENESIS)

RAIDEN_TEMPLATE="raiden \
    --eth-rpc-endpoint 127.0.0.1:${GETHPORT} \
    --listen-address 0.0.0.0:%s \
    --keystore-path=%s \
    --address=%s \
    $RAIDEN_CONTRACTS \
    --logging ':DEBUG' \
    --logfile %s"

RAIDEN_VARIABLE_TEMPLATE="
raiden1='${ADDRESS1}'
raiden2='${ADDRESS2}'
raiden3='${ADDRESS3}'
asset1='${TOKEN1}'
asset2='${TOKEN2}'
asset3='${TOKEN3}'
am1=raiden.get_manager_by_asset_address('${TOKEN1}'.decode('hex'))
am2=raiden.get_manager_by_asset_address('${TOKEN2}'.decode('hex'))
# am3=raiden.get_manager_by_asset_address('${TOKEN3}'.decode('hex'))"

[ "$SETUP_TMUX" -eq 1 ] && {
    info "creating the tmux windows/panels"

    tmux new-session -d -s raiden

    tmux new-window -t raiden:2 -n geth
    tmux new-window -t raiden:3 -n client1
    tmux new-window -t raiden:4 -n client2
    tmux new-window -t raiden:5 -n client3

    tmux send-keys -t raiden:2 "$INIT" C-m
    tmux send-keys -t raiden:3 "$INIT" C-m
    tmux send-keys -t raiden:4 "$INIT" C-m
    tmux send-keys -t raiden:5 "$INIT" C-m

    tmux send-keys -t raiden:2 "geth --datadir ${TEMP} init ${GENESIS}" C-m
    tmux send-keys -t raiden:2 "geth --datadir ${TEMP} --password ${TEMP}/password account new" C-m
    tmux send-keys -t raiden:2 "geth --minerthreads 1 --nodiscover --rpc --rpcport ${GETHPORT} --mine --etherbase 0 --datadir ${TEMP}" C-m

    tmux send-keys -t raiden:3 "$(printf "$RAIDEN_TEMPLATE" 40001 "${KEYSTORE1}" "${ADDRESS1}" "${LOG1}")" C-m
    tmux send-keys -t raiden:4 "$(printf "$RAIDEN_TEMPLATE" 40002 "${KEYSTORE2}" "${ADDRESS2}" "${LOG2}")" C-m
    tmux send-keys -t raiden:5 "$(printf "$RAIDEN_TEMPLATE" 40003 "${KEYSTORE3}" "${ADDRESS3}" "${LOG3}")" C-m
    # wait for all password prompts to appear:
    sleep 20
    tmux send-keys -t raiden:3 "$(printf "nopassword")" C-m
    tmux send-keys -t raiden:4 "$(printf "nopassword")" C-m
    tmux send-keys -t raiden:5 "$(printf "nopassword")" C-m

    followlog raiden:3 $LOG1
    followlog raiden:4 $LOG2
    followlog raiden:5 $LOG3

	tmux last-pane -t raiden:3
	tmux last-pane -t raiden:4
	tmux last-pane -t raiden:5
}

[ "$SETUP_CHANNELS" -eq 1 ] && {
    info "configuring the raiden channels"
    printf "      %64s %40s %s\n" PRIVKEY ADDRESS CHANNELS
    echo "node1 ${PRIVKEY1} ${ADDRESS1} both assets with balance"
    echo "node2 ${PRIVKEY2} ${ADDRESS2} both assets with balance"
    echo "node3 ${PRIVKEY3} ${ADDRESS3} both assets but asset2 has no balance"

    # assume the genesis file alredy has distributed asset to all nodes

    tmux send-keys -t raiden:3 "tools.register_asset('${TOKEN1}')" C-m
    tmux send-keys -t raiden:3 "tools.register_asset('${TOKEN2}')" C-m
    # tmux send-keys -t raiden:3 "tools.register_asset('${TOKEN3}')" C-m

    tmux send-keys -t raiden:4 "import time; time.sleep(10)  # wait for asset registration"  C-m
    tmux send-keys -t raiden:5 "import time; time.sleep(10 + 10)  # wait for asset registration and channel openning"  C-m

    tmux send-keys -t raiden:3 "tools.open_channel_with_funding('${TOKEN1}', '${ADDRESS2}', 100)" C-m
    tmux send-keys -t raiden:3 "tools.open_channel_with_funding('${TOKEN2}', '${ADDRESS2}', 100)" C-m

    tmux send-keys -t raiden:4 "tools.open_channel_with_funding('${TOKEN1}', '${ADDRESS3}', 100)"  C-m
    tmux send-keys -t raiden:4 "tools.open_channel_with_funding('${TOKEN2}', '${ADDRESS3}', 100)"  C-m

    tmux send-keys -t raiden:4 "tools.deposit('${TOKEN1}', '${ADDRESS1}', 100)" C-m
    tmux send-keys -t raiden:4 "tools.deposit('${TOKEN2}', '${ADDRESS1}', 100)" C-m

    tmux send-keys -t raiden:5 "tools.deposit('${TOKEN1}', '${ADDRESS2}', 100)"  C-m
}

[ "$SETUP_VARIABLES" -eq 1 ] && {
    tmux send-keys -t raiden:3 "${RAIDEN_VARIABLE_TEMPLATE}" C-m
    tmux send-keys -t raiden:4 "${RAIDEN_VARIABLE_TEMPLATE}" C-m
    tmux send-keys -t raiden:5 "${RAIDEN_VARIABLE_TEMPLATE}" C-m

    tmux send-keys -t raiden:3 "identifier = 1  # change this for each new transfer"
    tmux send-keys -t raiden:3 "raiden.api.expect_exchange(identifier, '${TOKEN1}'.decode('hex'), 100, '${TOKEN2}'.decode('hex'), 70,  '${ADDRESS3}'.decode('hex'))"

    tmux send-keys -t raiden:5 "identifier = 1  # change this for each new transfer"
    tmux send-keys -t raiden:5 "raiden.api.exchange(identifier, '${TOKEN1}'.decode('hex'), 100, '${TOKEN2}'.decode('hex'), 70,  '${ADDRESS1}'.decode('hex'))"
}

echo
echo 'tmux sesion created, attach to it using the following command:'
echo
msg "tmux attach-session -t raiden && rm -rf ${TEMP}"
echo
