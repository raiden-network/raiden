import json
from dataclasses import asdict, dataclass
from pathlib import Path

import click

from raiden.utils.claim import parse_claims_file
from raiden.utils.formatting import to_checksum_address


@dataclass(unsafe_hash=True)
class Node:
    id: str
    label: str
    size: int


@dataclass(unsafe_hash=True)
class Edge:
    id: str
    source: str
    target: str


@click.command()
@click.option("-i", "--input-file", default=Path("./claims.jsonl"), type=click.Path())
@click.option("-o", "--output-file", default=Path("./graph.json"), type=click.Path())
def convert(input_file: Path, output_file: Path,) -> None:
    nodes = set()
    edges = set()

    _, claims_generator = parse_claims_file(Path(input_file))
    for claim in claims_generator:
        owner = to_checksum_address(claim.owner)
        partner = to_checksum_address(claim.partner)

        nodes.add(Node(id=owner, label=owner, size=1))
        nodes.add(Node(id=partner, label=partner, size=1))

        edges.add(Edge(id=f"e{len(edges)}", source=owner, target=partner))

    result = {"nodes": [asdict(node) for node in nodes], "edges": [asdict(edge) for edge in edges]}

    output_file.write_text(json.dumps(result))


if __name__ == "__main__":
    convert()
