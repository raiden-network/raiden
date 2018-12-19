---
name: Bug Report
about: Non critical bug reports about the Raiden Network
---

<!--## Intro

Use this template to report non-critical bugs. For critical bugs, anything that may involve loss or locking of funds, please submit the report to bounty@raiden.network.


## Issue checklist

To help us more easily debug your issue please check the boxes for which requirements for safe usage or Raiden were followed:

- [ ] The Ethereum node was always up to date with the chain tip and never stopped running.
- [ ] No Ethereum transaction was sent for the account that Raiden manages by another app.
- [ ] The Ethereum account used by Raiden always had sufficient ETH.
- [ ] The Raiden DB that exists by default at ~/.raiden was never altered or deleted.
- [ ] The Raiden node was never restarted. If yes please provide more info.
- [ ] The ethereum node was not switched while Raiden was running.
- [ ] The Raiden REST API is protected from public access.

-->

## Problem Definition

Provide a description of what is the current problem and why you are raising this issue.
If it's a bug please describe what was the unexpected thing that occured and what was the
expected behaviour.

Raiden also logs debug information to the `raiden-debug.log` file. Please attach it to the
issue as it may help us find the source of the issue faster. It would also help if you provide us with the database located under `~/.raiden/node_xxxxxx/netid_x/network_xxxx/`. If you are on the mainnet and would like to keep your data private you can encrypt them and send it to us via email. Read [here](https://github.com/raiden-network/raiden/blob/master/CONTRIBUTING.md#including-sensitive-data-in-your-issue-reports) to see how the process works.

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
