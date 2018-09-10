#!/usr/bin/python3
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta

import click
import requests
import structlog
from web3 import IPCProvider, Web3
from web3.utils.compat.compat_stdlib import Timeout

log = struct.get_logger(__name__)

# Since this will run inside a docker container and is written for Python 3 we
# have to disable flake8 since it will run with Python 2 and break on Travis-CI
# flake8: noqa

"""
Helper script to start geth.

Due to the ropsten revival there are a lot of nodes that aren't on the "correct" chain.
To ensure nodes sync to the "right" chain a rather involved process is necessary:
https://github.com/ethereum/ropsten/blob/master/README.md#troubleshooting

This scripts automates this process:
* Start geth with `--nodiscover`
* Add "known good" nodes via JS-API
* Wait until initial sync is done
* Restart geth w/o `--nodiscover`
"""


BOOTNODES = [
    # Ropsten README
    # "enode://6ce05930c72abc632c58e2e4324f7c7ea478cec0ed4fa2528982cf34483094e9cbc9216e7aa34969124"
    # "2576d552a2a56aaeae426c5303ded677ce455ba1acd9d@13.84.180.240:30303",
    # "enode://20c9ad97c081d63397d7b685a412227a40e23c8bdc6688c6f37e97cfbc22d2b4d1db1510d8f61e6a886"
    # "6ad7f0e17c02b14182d37ea7c3c8b9c2683aeb6b733a1@52.169.14.227:30303",
    # BB "ropster"
    "enode://bed9a7af25633bbbb7bf23bfeb1518e2601868953d4b9dfcc490d00a5dd2c3ca17580fe23dcfb69208757"
    "465d6e517109fd17b9cdfcccdc4a2cd2bdd81f93e1a@134.119.11.28:30303",
    # https://gist.github.com/rfikki/7a95067f8cc02ae8b11bc34544f6aa3e#Ropsten-Peers-06282017.txt
    "enode://00ae60771d9815daba35766d463a82a7b360b3a80e35ab2e0daa25bdc6ca6213ff4c8348025e7e1a908a8"
    "f58411a364fe02a0fb3c2aa32008304f063d8aaf1a2@163.172.132.85:30303",
    "enode://0a4d29ff55bc331bf4850bb967074beb02a2fc235c5fbd4511db57ed98781d5d75590368d69b3014d62fa"
    "ab0d6146ce5221bf7e72a22404d7423c5e025019396@109.62.202.54:14574",
    "enode://0f838387f82e14ffabaa6c48812ce0b33f79444ffd1d36d82f5e101803375e3911583fee2703ec3205d3c"
    "729c2b0eb86d9fbb5de5bcadeff3aa05297a0af12e6@52.174.187.98:48036",
    "enode://18a5676911f520ff7fd04013227513a0f2a0cea1bc39a53d3d6afc8f476d9e600db65a3235ea74ab363da"
    "64c183d1f24c9f6fc606ab6f818e42049607d5b8e64@50.202.110.126:60668",
    "enode://37a6360cf1597cfe9ba5c242b247137f7a222e86e5c2d23e483eeb314b794648f71dedb2c15ad85b8ad85"
    "9f32b51c23e280982dd35b35d4432c963f3088e7165@31.16.253.42:8183",
    "enode://3dd0079b86d9a126010a1b6b41ef2ca0227a839f5132a222e10bc8ebc25a180317fb00b4470cb4dd599e1"
    "3ba330969c2d24b01231b8ba627be6845fdb0a69677@208.76.2.246:3872",
    "enode://3fa5f2525f8edf67abcec110d7dd4d98e1ea936f618f10ea3418c6db3faf065258a7e652097e69275749e"
    "921df9523ceabeaac2c702bbdff4ee1e89fe75dd932@217.234.145.135:49286",
    "enode://4814abeb1d62f924861cfd53503eb8d16a8375f5061f5b109cf4f83cbddf9605caf6ae99ea4ec515b4deb"
    "adeb172183edb1119d65e15abb5430b2737e157a810@188.60.170.25:45594",
    "enode://4df3e91d952d96546adce09dfa279cc4617d98a9d88eda1a31a2214ec908632f545d5283ecb7816ce3052"
    "3c9eb011348fa42a431a31ed2f3ca7d45f040c70bac@45.27.21.43:53576",
    "enode://70aab01dbb9b8c9676a41c8458dfabe874777eb06a925692fc8901d575befb609e98fdc1023268003c6c0"
    "9ac156f1cbbc22a2ba568eafbc32bbd40d62edd02db@46.53.177.238:51176",
    "enode://7db1dd1c123eac9ef7f4a9e999c0abe2a5ec9886b61d2366645ff508e02455d7f139cc9fdfc84ca2b0ea4"
    "11da1552d93a2508d3dacc3ef6704ff47a38426cb4a@216.151.184.87:53754",
    "enode://82a91578bcc39447f084aba14f932056cc09bd57e3ac1be039c5f3202eeb7281a512da0a664fa3b10d935"
    "4c1604db3b56d8bb585e2006c6fd24761c5a50056f0@99.235.74.76:43352",
    "enode://86ebc843aa51669e08e27400e435f957918e39dc540b021a2f3291ab776c88bbda3d97631639219b6e77e"
    "375ab7944222c47713bdeb3251b25779ce743a39d70@212.47.254.155:30303",
    "enode://8ab78987908454be92f4aadbe379245cbf0e472547ede2f3efebc0ca733c51ed895515300a04f2ca60ccf"
    "a0455f68d56f4734b2b931a0232594967c50f6b42cc@54.196.249.59:36388",
    "enode://8b88dabdfdca2c7aab160b1a26c7e5be855bf55ed4dda05b176dee1d09fe00e1a1a6bce73585dbbbd3f05"
    "cd94259dbe8fe201af0283a5a40a33408e4184df550@84.200.105.107:39521",
    "enode://90f0c67ede3ff110d47cb76d44499105f337dca4046bef73b6fed8fc4b9bbf488917c96442c2f80e84894"
    "9f77478893fc9dbefadf9a92414cb44677c2890ca69@52.233.195.36:1440",
    "enode://9588c5cc481de306217d97e055312ded57276ee46beb6ff834b2aa46ed67e6b941fc99098aabece0cecec"
    "0bf6f536d9c0e2337c0166a8ef49dc564440ddac8ed@124.169.136.13:51075",
    "enode://9f2afd7068309d43adc91cd6f4dc41cbd69a9b9b3ea9ef8f3109cac395d3e08256b08a23fbccded6a7879"
    "f00f05ed4b385047216373291466a8e4066f56977b5@12.46.122.13:24437",
    "enode://aa927af666de44bbbe8ea6e0b3665125c1afed8841bb1c26daf10b0cf1b1683e9ceac49bdf2779ec0a954"
    "e1d64ff98b7d5126f2feb7c6a37dba068038646676a@72.221.17.212:63725",
    "enode://bf6848d2a994079293da3fa378bb9d228c0ae3e474ba5708d1719195044746cdaaa129801db8d0c86f24d"
    "fff92963f6f58905b7fa06b3440d723208253516516@172.56.38.223:23377",
    "enode://c2e2667ff2edb243160677a9452f4d4afff64645f0b39cd21e2b284567fa9e66279493763cfb63b1efda1"
    "5b3608eb8bbd9f436bedbd22506f061cea3c222f72e@80.98.178.136:55803",
    "enode://d42a19638fadfbc19991a1e9ab92055ea49209890d05405813d898cd769716d0de646ba13a07ab7f5ae3b"
    "e476a166f6e5f15310a4aedf915212b045a3bebafe3@200.52.79.154:41694",
    "enode://e2f51ca80c2cd6e1129f8b9769f59f2ff2d6a9579c07a244bde1b7c4dc7d18fcb8c4e951b1f131d22252e"
    "4056c5f7a71958eb4e3286536a4b7c9b4b6bc2aa595@132.205.229.18:60102",
    "enode://fe991752c4ceab8b90608fbf16d89a5f7d6d1825647d4981569ebcece1b243b2000420a5db721e214231c"
    "7a6da3543fa821185c706cbd9b9be651494ec97f56a@51.15.67.119:56890",
]

ETHERSCAN_API_BLOCKNO = "https://ropsten.etherscan.io/api?module=proxy&action=eth_blockNumber"

GETH_PATH = "/usr/local/bin/geth"
GETH_CMD_RUN = [GETH_PATH, "--testnet", "--fast", "--rpc", "--rpcaddr", "0.0.0.0"]
GETH_CMD_RUN_INITIAL = [*GETH_CMD_RUN, "--nodiscover"]

# Max delay before syncing must have started
SYNC_START_DELAY = 120

# Percentage when we consider sync to be done
# XXX: FIXME: This is a hack to keep the node in "boot mode" (i.e. --nodiscover)
SYNC_FINISHED_PCT = 110


def get_current_block_no():
    try:
        return int(requests.get(ETHERSCAN_API_BLOCKNO).json()['result'], 0)
    except (ValueError, KeyError):
        return 0


@click.command()
@click.option("-b", "--bootnode", multiple=True, default=BOOTNODES)
def main(bootnode):
    geth_proc = subprocess.Popen(GETH_CMD_RUN_INITIAL)

    # Give node some time to start up
    time.sleep(5)

    web3 = Web3(IPCProvider(testnet=True))

    try:
        web3.eth.syncing
    except FileNotFoundError:
        log.critical("Can't connect to geth ipc port - check previous output")
        geth_proc.terminate()
        sys.exit(1)

    for node in bootnode:
        web3.admin.addPeer(node)
        log.info("Adding bootnode %s", node)

    log.info("Added bootnodes")

    start = time.monotonic()
    err_cnt = 0
    synced = False
    while geth_proc.poll() is None:
        time.sleep(5)

        try:
            sync_state = web3.eth.syncing
            block_number = web3.eth.blockNumber
            err_cnt = 0
        except Timeout:
            err_cnt += 1
            if err_cnt > 10:
                log.critical("Timeout connecting to geth")
                geth_proc.terminate()
                sys.exit(3)
            log.warning("Timeout connecting to geth, retrying.")
            continue

        if sync_state is False:
            if abs(block_number - get_current_block_no()) < 5:
                log.info("Node is already synced")
                synced = True
                break
            if time.monotonic() - start > SYNC_START_DELAY:
                log.critical("Node hasn't started syncing after {}s".format(SYNC_START_DELAY))
                geth_proc.terminate()
                sys.exit(2)
            continue

        if sync_state['currentBlock'] / sync_state['highestBlock'] * 100 >= SYNC_FINISHED_PCT:
            log.info("Syncing done")
            synced = True
            break
        else:
            duration = time.monotonic() - start
            blocks_synced = sync_state['currentBlock'] - sync_state['startingBlock']
            blocks_remaining = sync_state['highestBlock'] - sync_state['currentBlock']
            blocks_per_sec = blocks_synced / duration
            time_remaining = timedelta(
                seconds=int(blocks_remaining / blocks_per_sec) if blocks_per_sec else 0)
            log.info("Blocks remaining: {:,d}; blk/s: {:.1f}; ETA: {!s} / {:%H:%M}".format(
                blocks_remaining,
                blocks_per_sec,
                time_remaining,
                datetime.now() + time_remaining
            ))

    geth_proc.send_signal(signal.SIGINT)
    geth_proc.wait(10)

    if not synced:
        log.critical("Geth terminated without finished syncing")
        sys.exit(4)

    log.info("Restarting geth")
    os.execv(GETH_PATH, [*GETH_CMD_RUN, "--bootnodes", ",".join(bootnode)])


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    main()
