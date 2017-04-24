# Scenario: Asset exchange
- User Alice wants to exchange N asset X for M asset Y with user Charlie
- Alice and Charlie have accounts for both assets

**Solution:**
As described in the presentation. Two asset transfers with same hashlock allow to atomically swap assets in a certain ration. See `ExchangeRequest` and `ExchangeTask` in the code.

# Scenario: Asset transfer with different source and destination assets
- User Alice wants to transfer N of asset X to user Charlie for at most M of asset Y 
- Alice and Charlie both only have an account for on of the assets

**Solution**
New MediatedAXTransfer message which additionally specifies: `target_asset`, `target_amount`.
Every hop checks the channelgraph if there is path with a node which has accounts for both assets. A node with both assets would accept the source_asset and forward the transfer as the target_asset, if it agrees with the source_amount, target_amount ratio. As with the MediatedTransfer, we'll have optimistic routing i.e. as there is no global view on the transfer capacity (deposit/balance) and the exchange rate of the nodes. If a node can not successfully transfer, it reports this back to the calling node which tries the next best path.
