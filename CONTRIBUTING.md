# Raiden Development Guide

Welcome! This guide serves as the guideline to contributing to the Raiden Network
codebase. It's here to help you understand what developmenr practises we use here
and what are the requirements for a Pull Request to be opened against Raiden.

- [Contributing](#contributing)
    - [Creating an Issue](#creating-an-issue)
    - [Creating a Pull Request](#creating-a-pull-request)
- [Development Guidelines](#development-guidelines)
    - [Coding Style](#coding-style)
    - [Workflow](#workflow)


## Contributing

You can contribute to the development with two basic methods. You can either open
an Issue or if you have programming abilities open a Pull Request.

### Creating an Issue

If you experience a problem while using Raiden or want to request a feature then you should open an issue against the repository. All issues should contain:

**For Feature Requests:**
- A description of what you would like to see implemented
- An explanation of why you believe this would make a good addition to Raiden

**For Bugs:**
- A short description of the problem
- Detailed description of your system, raiden version, geth version, solidity version e.t.c.
- What was the exact unexpected thing that occured
- What you were expecting to happen instead

### Creating a Pull Request

If you have some coding abilities and would like to contribute to the actual codebase of Raiden then you can open a Pull Request(PR) against the repository.

All PRs should be:
- Self-contained
- As short as possible and address a single issue or even a part of an issue.
If the PR adds a new feature and it's very long, consider breaking into smaller ones.

In order for a Pull Request to get merged into the main repository you should have one
approved review from one of the core developers of Raiden and also all Continuous integration tests should be passing and the CI build should be green.

## Development Guidelines

In this section we are going to describe the coding rules for contributing to the raiden repository. All code you write should strive to comply with these rules.

### Coding Style

Raiden is written in Python and we follow the official Python style guide [PEP8](https://www.python.org/dev/peps/pep-0008/). It is highly
recommended to use the [flake8](https://pypi.python.org/pypi/flake8) tool in order to automatically determine any and all style violations. The customizeable part of flake can be seen in the [configuration file](setup.cfg). For all the rest which are not
configurable here is some general guidelines.

** Line Length **
Flake8 will warn you for 99 characters which is the hard limit on the max length. Try not to go above it. We also have a soft
limit on 80 characters but that is not enforced and is there just to encourage short lines.

** Breaking function definitions when line is above 99 characters **

Always put each argument into its own line. Look at the following examples to understand:

The following should be avoided
```python

def function_with_many_args(argument1, argument2, argument3, argument4, argument5, argument6, argument7):
	pass
```

and instead you should

```python

def function_with_many_args(
    argument1,
    argument2,
    argument3,
    argument4,
    argument5,
    argument6,
    argument7):
	pass
```


** Breaking function calls when line is above 99 characters **

Much like in the above example the following should be avoided

```python

function_call_with_many_arguments(argument1, argument2, argument3, argument4, argument5, argument6, argument7)

```

and instead you should

```python

function_call_with_many_arguments(
    argument1,
    argument2,
    argument3,
    argument4,
    argument5,
    argument6,
    argument7
)
```

Difference being that you can place the closing parentheses in the next line.


**Naming Style**

Use [Snake Case](https://en.wikipedia.org/wiki/Snake_case) for variable and function names and [Camel Case](https://en.wikipedia.org/wiki/Camel_case) for class names.

**Naming Convention**

Use descriptive variable names and avoid short abbreviations.


The following is bad:
```python
mgr = Manager()
a = AccountBalanceHolder()
s = RaidenService()
```

While this is good:

```python
manager = Manager()
balance_holder = AccountBalanceHolder()
service = RaidenService()
```

### Workflow

When developing a feature, or a bug fix you should always start by writting a **test** for it, or by modifying
existing tests to test for your feature. Once you see that test failing you should implement the feature and confirm
that all your new tests pass.

Afterwards you should open a Pull Request from your fork or feature branch against master. You will be given feedback from
the core developers of raiden and you should try to incorporate that feedback into your branch. Once you do so and all tests
pass your feature/fix will be merged.
