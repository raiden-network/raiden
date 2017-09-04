from __future__ import print_function
import os

import click
import re

import sys
from click.types import File

IMPORT_RE = re.compile(r'^import +["\'](?P<contract>[^"\']+.sol)["\'];$')

"""
Utility to join solidity contracts into a single output file by recursively
resolving imports.

example usage:

$ cd raiden/smart_contracts
$ python ../../tools/join-contracts.py SomeContractWithImports.sol joined.sol

"""


class ContractJoiner(object):
    def __init__(self):
        self.have_pragma = False
        self.seen = set()

    def join(self, contract_file):
        out = []
        if contract_file.name in self.seen:
            print('Skipping duplicate {}'.format(contract_file.name), file=sys.stderr)
            return []

        self.seen.add(contract_file.name)
        print('Reading {}'.format(contract_file.name), file=sys.stderr)

        for line in contract_file:
            line = line.strip('\r\n')
            stripped_line = line.strip()
            if stripped_line.startswith('pragma'):
                if not self.have_pragma:
                    self.have_pragma = True
                    out.append(line)
            elif stripped_line.startswith('import'):
                match = IMPORT_RE.match(stripped_line)
                if match:
                    next_file = match.groupdict().get('contract')
                    if next_file and os.path.exists(next_file):
                        with open(next_file) as next_contract:
                            out.extend(self.join(next_contract))
            else:
                out.append(line)
        return out


@click.command()
@click.argument('contract', type=File())
@click.argument('output', type=File('w'))
def main(contract, output):
    output.write("\n".join(ContractJoiner().join(contract)))


if __name__ == '__main__':
    main()
