# Tools for Raiddit

## Claim Generator

Tool to generate the `claims.json` to be consumed by the Raiden modules building up a network topology. 

### Hub

Generates a star topology with a Raiden Hub address in the middle. The hub address is partner in every channel. Every side of the channel will be funded with `DEFAULT_AMOUNT_TOKEN`.

`python tools/raiddit/generate_claims.py hub --address 0xMY_ADDRESS --token-network-address 0xTOKEN_NETWORK`

```
Options:
  --address ADDRESS               Own address  [required]
  --token-network-address ADDRESS              [required]
  --chain-id CHAINID
  -h, --hub-address ADDRESS
  -u, --users INTEGER             How many users claims should be generated
                                  for
  -o, --output-file PATH
  --help                          Show this message and exit.
```