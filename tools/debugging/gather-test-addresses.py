import json
import re
import string
from json import JSONDecodeError
from typing import Any, Dict, List, Optional, Set, TextIO

import click
from eth_utils import to_checksum_address
from eth_utils.typing import ChecksumAddress

EVENT_FIELD_REGEXES = {
    "node": re.compile(r"(0x[0-9a-fA-F]{40})"),
    "current_user": re.compile("@(0x[0-9a-fA-F]{40}):.+"),
    "greenlet_name": re.compile(".+node:(0x[0-9a-fA-F]{40}).*"),
}


def _to_base_26(value: int) -> str:
    alphabet = string.ascii_uppercase
    output: List[str] = []
    if value == 0:
        output = [alphabet[0]]
    while value > 0:
        output.append(alphabet[value % 26])
        value //= 26
    return "".join(reversed(output))


def get_record_address(record: Dict[str, Any]) -> Optional[ChecksumAddress]:
    for event_field, field_regex in EVENT_FIELD_REGEXES.items():
        if event_field in record:
            match = field_regex.match(record[event_field])
            if match:
                return to_checksum_address(match.group(1))


def find_node_addresses(input_file: TextIO) -> Set[ChecksumAddress]:
    addresses = set()
    for line in input_file:
        try:
            record = json.loads(line)
        except (JSONDecodeError, UnicodeDecodeError):
            continue
        address = get_record_address(record)
        if address:
            addresses.add(address)
    return addresses


@click.command(
    help=(
        "Collect node addresses used in a test run log file. "
        "Writes a json-log-to-html compatible replacements file."
    )
)
@click.argument("input-file", type=click.File("rt"))
@click.argument("output-file", type=click.File("wt"), default="-")
def main(input_file, output_file):
    node_addresses = find_node_addresses(input_file)
    click.secho(f"Found {len(node_addresses)} addresses", fg="green", err=True)
    for node_address in sorted(node_addresses):
        click.secho(f"  - {node_address}", fg="blue", err=True)
    replacements = {
        address: f"<<{_to_base_26(i)}>>" for i, address in enumerate(sorted(node_addresses))
    }
    output_file.write(json.dumps(replacements))
    click.secho(f"Wrote replacements to {output_file.name}", fg="green", err=True)


if __name__ == "__main__":
    main()
