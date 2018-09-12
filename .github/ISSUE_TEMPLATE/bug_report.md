---
name: Bug Report
about: Non critical bug reports about the Raiden Network
---

<!--## Intro

Use this template to report non-critical bugs. For critical bugs, anything that may involve loss or locking of funds, please submit the report to bounty@raiden.network.
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
