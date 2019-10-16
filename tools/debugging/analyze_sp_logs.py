#!/usr/bin/env python

"""
Helper script for debugging scenario player runs. It provides an assistant
for running `replay_wal.py` on the DBs contained in the scenario player's
combined log output.
Specifically it will help you to select
- the `run_number` to analyze (latest by default)
- the `token_network_address`
- the `db_file`
- the `partner_address`

For human beings, it gives names to all addresses, that will also feed the `--names-translator`
option of `replay_wal`.

Usage:
    analyze_sp_logs.py [OPTIONS] FOLDER

Example:
    analyze_sp_logs.py /tmp/debug/mfee4_combined_fees
"""

import json
import os
import tempfile
from glob import glob
from typing import Any, Dict, List, Optional, Set, Tuple, cast

import click
from replay_wal import main as replay_wal

USERNAMES = [
    "Alice",
    "Bob",
    "Carol",
    "Dan",
    "Erin",
    "Frank",
    "Grace",
    "Heidi",
    "Ivan",
    "Judy",
    "Karl",
    "Luke",
    "Michael",
    "Nina",
    "Olivia",
    "Peggy",
    "Quentin",
    "Rupert",
    "Sybil",
    "Trudy",
    "Ulrich",
    "Victor",
    "Walter",
    "Xaver",
    "Yahoo",
    "Zorro",
]


class ScenarioItems:
    def __init__(self) -> None:
        self.scenario_log: Optional[os.PathLike] = None
        self.users: Dict[str, Any] = dict()
        self.token_networks: List[str] = []
        self.db_files: Dict[str, Any] = dict()

    def __repr__(self) -> str:
        return json.dumps(self.__dict__)

    def add_user(self, address: str, db_file: os.PathLike) -> None:
        name = USERNAMES[len(self.users)]
        self.users[name] = address
        self.db_files[name] = db_file

    def write_translator(self) -> str:
        translator_file = tempfile.mktemp(prefix="trans_", suffix=".json")
        with open(translator_file, "w") as f:
            json.dump({v: k for k, v in self.users.items()}, f)
        return translator_file


def detect_scenario_player_log(fn: os.PathLike) -> bool:
    with open(fn) as f:
        for line in f.readlines():
            if json.loads(line).get("logger") == "scenario_player.main":
                return True
    return False


def get_nodes(fn: os.PathLike) -> List[str]:
    with open(fn) as f:
        for line in f.readlines():
            if "Node eth balances" in line:
                balances = json.loads(line)
                return list(balances["balances"].keys())
    raise ValueError("Incompatible log file, could not find nodes")


def get_token_network_addresses(fn: os.PathLike) -> List[str]:
    token_networks: Set[str] = set()
    with open(fn) as f:
        for line in f.readlines():
            if "Token Network Discovery" in line:
                logline = json.loads(line)
                if logline["event"] == "Token Network Discovery":
                    token_networks.add(logline["network"])
    return list(token_networks)


def find_last_run(folder: os.PathLike) -> int:
    if "run_number.txt" in os.listdir(folder):
        with open(os.path.join(folder, "run_number.txt")) as f:
            return int(f.read().strip())
    node_folders = glob(os.path.join(folder, "node_*"))
    run_numbers = [int(node_folder.rsplit("_", 2)[-2]) for node_folder in node_folders]
    return max(run_numbers)


def parse_node_folder(
    folder: os.PathLike, node_number: int, run_number: int, known_addresses: List[str]
) -> Tuple[str, os.PathLike]:
    node_path = os.path.join(folder, f"node_{run_number}_{node_number:03}")
    account_address = json.load(open(glob(os.path.join(node_path, "keys/*"))[0]))["address"]
    node_address = known_addresses[
        [address.lower() for address in known_addresses].index("0x" + account_address)
    ]
    db_file = cast(os.PathLike, glob(os.path.join(node_path, "node_*/netid*/network*/*.db"))[0])
    if not os.path.exists(db_file):
        raise ValueError(f"Could not find db for {node_address} at {node_path}")
    return node_address, db_file


def select_by_number(options: Any, caption: str) -> Any:
    if len(options) == 1:
        print(f"{caption} \n-> Autoselected the only option: {options[0]}")
        return list(options)[0]
    value = None
    for i, option in enumerate(options):
        if isinstance(options, dict):
            print(f"[{i}] {option:7} - {options[option]}")
        else:
            print(f"[{i}] {option}")
    while value is None:
        selected = input(f"{caption} ")
        try:
            value = list(options)[int(selected)]
        except (IndexError, ValueError):
            print(f"Incorrect selection {selected}")
    return value


@click.command(help=__doc__)
@click.option(
    "-r",
    "--run-number",
    help="use a specific run number (Default: highest)",
    type=int,
    default=None,
)
@click.argument("folder", type=click.Path(exists=True, file_okay=False))
@click.pass_context
def main(ctx: Any, folder: os.PathLike, run_number: Optional[int]) -> None:
    scenario = ScenarioItems()
    content: List[os.PathLike] = cast(List[os.PathLike], os.listdir(folder))
    for fn in content:
        file = os.path.join(folder, fn)
        if os.path.isfile(file) and detect_scenario_player_log(file):
            scenario.scenario_log = file
            break
    if scenario.scenario_log is None:
        raise ValueError("Could not find scenario player log file")
    print(scenario.scenario_log)
    scenario.token_networks = get_token_network_addresses(scenario.scenario_log)
    nodes = get_nodes(scenario.scenario_log)
    if run_number is None:
        run_number = find_last_run(folder)
    print(f"Parsing run [{run_number}].")
    for node_number in range(len(nodes)):
        user_address, db_file = parse_node_folder(folder, node_number, run_number, nodes)
        scenario.add_user(user_address, db_file)
    token_network = select_by_number(scenario.token_networks, "Select token_network:")
    node = select_by_number(scenario.users, "Select node DB:")
    partner = select_by_number(scenario.users, "Select partner:")
    translator = scenario.write_translator()
    db_file = scenario.db_files[node]
    partner_address = scenario.users[partner]
    print(
        f"Replaying WAL DB:\n\t{db_file}\n\tNode:    {node} {scenario.users[node]}\n\t"
        f"Partner: {partner} {partner_address}\n\tToken Network: {token_network}"
    )
    with open(translator) as names_translator:
        ctx.invoke(
            replay_wal,
            db_file=db_file,
            token_network_address=token_network,
            partner_address=partner_address,
            names_translator=names_translator,
        )


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
