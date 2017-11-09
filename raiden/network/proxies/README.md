Coding standard for this module:

- Be sure to reflect changes to this module in the test
  implementations. [tests/utils/*_client.py]
- Expose a synchronous interface by default
  - poll for the transaction hash
  - check if the proper events were emited
  - use `call` and `transact` to interact with client proxies
- Check errors:
  - `call` returns the empty string if the target smart contract does not
  exist or the call throws, handle it accordingly (there is no way to
  distinguish a function that returns the empty string from the error)
  - the smart contract executed with a `transact` may fail with a throw, this
  will spend all gas (there is no way to distinguish a transaction that used
  exactly all the available gas). Note: There is a new opcode in draft that
  wont use all gas https://github.com/ethereum/EIPs/pull/206
