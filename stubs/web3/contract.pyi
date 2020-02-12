from typing import Any, Dict

from web3 import Web3

from raiden.utils.typing import BlockSpecification, ChecksumAddress, TransactionHash


class Transactor:
    def __getattr__(self, function_name: str) -> TransactionHash:
        ...

class ContractFunctionReady:
    def call(self, transaction: Dict = ..., block_identifier: BlockSpecification = ...) -> Any:
        ...

    def transact(self, transaction: Dict) -> TransactionHash:
        ...

    def estimateGas(self, transaction: Dict) -> int:
        ...

class ContractFunction:
    def __call__(self, *args, **kwargs) -> ContractFunctionReady:
        ...

class ContractFunctions:
    def __getattr__(self, name: str) -> ContractFunction:
        ...

class ContractEvent:
    ...

class ContractEvents:
    def __getattr__(self, event_name: str) -> ContractEvent:
        ...

class Contract:
    web3: Web3
    abi: Dict
    address: ChecksumAddress
    functions: ContractFunctions
    events: ContractEvents

    def transact(self, transaction: Dict = ...) -> Transactor:
        ...
