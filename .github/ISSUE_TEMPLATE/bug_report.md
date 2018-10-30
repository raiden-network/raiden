---
name: Bug Report
about: Non critical bug reports about the Raiden Network
---

<!--## Intro

Use this template to report non-critical bugs. For critical bugs, anything that may involve loss or locking of funds, please submit the report to bounty@raiden.network.


## Issue checklist
Read through [Requirements for safe usage](https://raiden-network.readthedocs.io/en/stable/overview_and_guide.html#requirements-for-safe-usage) mentioned in our documentation and make sure your usage follows the requirements.

1. Is your Ethereum node syncing and up to date with the blockchain?
2. Are you using the same Ethereum account with anything other than the Raiden node? Or are you running multiple Raiden nodes with the same Ethereum account?
3. Does your Ethereum account used by Raiden have sufficient ETH?
4. Did you alter or delete the local DB that exists by default at ~/.raiden?
4. Did you stop / restart your raiden node while having open channels and/or pending transfers? if so, please provide further information.
5. Did you stop / restart your Ethereum node while Raiden was running?
6. Did you switch from one Ethereum node to another? example: switching from a local Ethereum node to an Infura one.
7. Is Raiden REST API protected from public access?

-->

## Problem Definition

Provide a description of what is the current problem and why you are raising this issue.
If it's a bug please describe what was the unexpected thing that occured and what was the
expected behaviour.

Raiden also logs debug information to the `raiden-debug.log` file. Please attach it to the
issue as it may help us find the source of the issue faster.

### System Description

Here add a detailed description of your system, e.g. output of the following script:

```
uname -a
command -v solc && solc --version
command -v geth && geth version
command -v parity && parity --version
command -v raiden && raiden version
[ -d .git ] && git rev-parse HEAD
```
