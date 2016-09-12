#!/usr/bin/sh

function waitfor() {
    while [[ ! -s $1 ]]; do sleep 1; done
}

function info() {
    # bold and blue
    printf "$(tput bold)$(tput setaf 4) -> $1$(tput sgr0)\n" >&1
}

msg() {
    # bold and green
    printf "$(tput bold)$(tput setaf 2) $1$(tput sgr0)\n" >&1
}

INIT=$1

GETHPORT=8101
TEMP=$(mktemp -d "/tmp/raiden.XXXXX")
ADDRESS_JSON="${TEMP}/contract_addresses.json"

PRIVKEY1=51c662cae295bdef5b0b895065aaa105089375e6541381dc17ba6d3ea0451052
PRIVKEY2=20d8b10d23ec1f00b54d798c9120fae94cff91e8db936affe6ef9d80a74c3535
PRIVKEY3=aa3e84aa62daa5186d75663ff09c62500b998fe143bdfbb1b7e29b8e5583970b

ADDRESS1=67febce7e8f81e6c6b6624a6cef64b4b717c0194
ADDRESS2=01551883681ba1eedf9403f743808776cc9e509a
ADDRESS3=397a25e3c9c66c870e2a044379da9429156aa05f

LOG1=${TEMP}/node1
LOG2=${TEMP}/node2
LOG3=${TEMP}/node3

tmux new-session -d -s raiden

tmux new-window -t raiden:2 -n geth
tmux new-window -t raiden:3 -n client1
tmux new-window -t raiden:4 -n client2
tmux new-window -t raiden:5 -n client3

tmux send-keys -t raiden:2 "$INIT" C-m
tmux send-keys -t raiden:3 "$INIT" C-m
tmux send-keys -t raiden:4 "$INIT" C-m
tmux send-keys -t raiden:5 "$INIT" C-m

tmux send-keys -t raiden:2 "python tools/startcluster.py" C-m
tmux send-keys -t raiden:3 "python tools/deploy.py ${GETHPORT} ${PRIVKEY1} > ${ADDRESS_JSON}" C-m

info "waiting for the contracts to be deployed"
waitfor ${ADDRESS_JSON}

ENDPOINT_ADDRESS=$(jq .EndpointRegistry ${ADDRESS_JSON})
REGISTRY_ADDRESS=$(jq .Registry ${ADDRESS_JSON})
RAIDEN_TEMPLATE="python raiden/app.py \
    --eth_rpc_endpoint 127.0.0.1:${GETHPORT} \
    --listen_address 0.0.0.0:%s \
    --privatekey=%s \
    --registry_contract_address=${REGISTRY_ADDRESS} \
    --discovery_contract_address=${ENDPOINT_ADDRESS} \
    --logging ':DEBUG' \
    --logfile %s"

tmux send-keys -t raiden:3 "$(printf "$RAIDEN_TEMPLATE" 40001 "${PRIVKEY1}" "${LOG1}")" C-m
tmux send-keys -t raiden:4 "$(printf "$RAIDEN_TEMPLATE" 40002 "${PRIVKEY2}" "${LOG2}")" C-m
tmux send-keys -t raiden:5 "$(printf "$RAIDEN_TEMPLATE" 40003 "${PRIVKEY3}" "${LOG3}")" C-m

tmux send-keys -t raiden:3 "token_address_hex = tools.create_token()" C-m
tmux send-keys -t raiden:3 "asset_proxy = raiden.chain.asset(token_address_hex.decode('hex'))" C-m
tmux send-keys -t raiden:3 "asset_proxy.transfer('${ADDRESS2}'.decode('hex'), 100000)" C-m
tmux send-keys -t raiden:3 "asset_proxy.transfer('${ADDRESS2}'.decode('hex'), 100000)" C-m

echo
echo 'tmux sesion created, attach to it using the following command:'
echo
msg 'tmux attach-session -t raiden'
echo
