Coding standard for this module:

- Expose a synchronous interface by default
  - poll for the transaction hash
  - check if the proper events were emited
  - use `call` and `transact` to interact with client proxies
- Check errors:
  - `call` returns the empty string if the target smart contract does not exist
    or the call fails, handle it accordingly (there is no way to distinguish a
    function that returns the empty string from the error)
  - the code may fail with a `require` or `revert`, for this instance the
    receipt will contain the status of the transaction.
  - the code may fail with an assert, this will spend all gas (there is no way
    to distinguish a transaction that used exactly all the available gas).
