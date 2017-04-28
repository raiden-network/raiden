# Raiden Development Guide

Welcome! This guide serves as the guideline to contributing to the Raiden Network
codebase. It's here to help you understand what development practises we use here
and what are the requirements for a Pull Request to be opened against Raiden.

- [Contributing](#contributing)
    - [Creating an Issue](#creating-an-issue)
    - [Creating a Pull Request](#creating-a-pull-request)
- [Development Guidelines](#development-guidelines)
    - [Coding Style](#coding-style)
    - [Workflow](#workflow)


## Contributing

There are two ways you can contribute to the development. You can either open
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
  Consider breaking long PRs into smaller ones.

In order for a Pull Request to get merged into the main repository you should have one
approved review from one of the core developers of Raiden and also all Continuous Integration tests should be passing and the CI build should be green.

## Development Guidelines

In this section we are going to describe the coding rules for contributing to the raiden repository. All code you write should strive to comply with these rules.

### Commiting Rules

For an exchaustive guide read [this](http://chris.beams.io/posts/git-commit/) guide. It's all really good advice. Some rules that
you should always follow though are:

- A commit title not exceeding 50 characters
- A blank line after the title (optional if there is no description)
- A description of what the commit did (optional if the commit is really small)

Why are these rules important? All tools that consume git repos and show you information treat the first 80 characters as a title.
Even Github itself does this. And the git history looks really nice and neat if these simple rules are followed.

### Encoding

Addresses should follow "sandwich encoding" so that each point of entry does its own encoding into binary but the core programmatic API
accepts only binary. Thus we setup the following rules:

- Programmatic API should only expect binary and break if it accepts anything else. It should do type checking on its input and provide meaningful error for hex encoded addresses
or length mismatch.
- All other places from which we receive addresses need to do their own encoding from whatever the input encoding is to binary. Such places are: CLI, Rest-API e.t.c.
- All modules which generate output to the outside world should also encode from binary to whatever the expected output encoding of that module is. Such places are stdout, communication with the ethereum node e.t.c.

### Coding Style

#### Python

Raiden is written in Python and we follow the official Python style guide [PEP8](https://www.python.org/dev/peps/pep-0008/). It is highly
recommended to use the [flake8](https://pypi.python.org/pypi/flake8) tool in order to automatically determine any and all style violations. The customizeable part of flake can be seen in the [configuration file](setup.cfg). For all the rest which are not
configurable here is some general guidelines.

**Line Length**
Flake8 will warn you for 99 characters which is the hard limit on the max length. Try not to go above it. We also have a soft
limit on 80 characters but that is not enforced and is there just to encourage short lines.

**Breaking function definitions when line is above 99 characters**

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


**Breaking function calls when line is above 99 characters**

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

**Usage of single and double quotes**

All strings must use single quotes by default.

Bad:

```python
s = "foo"
```

Good:

```python
s = 'foo'
```

The only reason to use double quotes is to avoid escaping the single quote in a string. So this is okay:

```python
s = "Augusto's computer is awesome"
```


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

We try to follow a consistent naming convention throughout the codebase to make it easy for the reader of the code to understand what is going on.
Thus we introduce the following rules:

For addresses:

- `<name>_address_hex` for hex encoded addresses
- `<name>_address` for binary encoded addresses

Lists of objects:

- `<name>s`, e.g. `channels` for a list `Channel` object instances.

Mappings/dicts:

`<name>s_to_<name>s`, e.g. `tokenaddresses_to_taskmanagers`

#### Solidity

For solidity we generally follow the style guide as shown in the [solidity documentation](http://solidity.readthedocs.io/en/develop/style-guide.html)
with a few notable exceptions:

**Variable Names**

All variable name should be in snake case, just like in python. Function names on the other hand should be mixedCase.
MixedCase is essentially like CamelCase but with the initial letter being a small letter.
This helps us to easily determine which function calls are smart contract calls in the python code side.

```js
function iDoSomething(uint awesome_argument) {
    doSomethingElse();
}
```

**Modifiers in long function declarations**


This is how the solidity documentation suggests it:

```js
function thisFunctionNameIsReallyLong(
    address x,
    address y,
    address z,
)
    public
    onlyowner
    priced
    returns (address)
{
    doSomething();
}
```

This is the minor modification we make in order to make the code more readable when quickly skimming through it.
The thinking here is to easily spot the start of the function's block when skimming and not have the modifiers
appearing as if they are a block on their own due to the hanging parentheses.

```js
function thisFunctionNameIsReallyLong(
    address x,
    address y,
    address z)

    public
    onlyowner
    priced
    returns (address)
{
    doSomething();
}
```



### Workflow

When developing a feature, or a bug fix you should always start by writting a **test** for it, or by modifying
existing tests to test for your feature. Once you see that test failing you should implement the feature and confirm
that all your new tests pass.

Afterwards you should open a Pull Request from your fork or feature branch against master. You will be given feedback from
the core developers of raiden and you should try to incorporate that feedback into your branch. Once you do so and all tests
pass your feature/fix will be merged.

#### Contributing to other people's PRs

If you are a core developer of Raiden with write privileges to the repository then you can add commits or rebase to master
any Pull Request by other people.

Let us take [this](https://github.com/raiden-network/raiden/pull/221) PR as an example. The contributor has everything ready
and all is looking good apart from a minor glitch. You can wait until he fixes it himself but you can always help him by
contributing to his branch's PR:

```
git remote add hackaugusto git@github.com:hackaugusto/raiden.git
git fetch hackaugusto
git checkout travis_build
```

Right now you are working on the contributor's Pull Request. **Make sure** to coordinate to avoid any conflicts and always warn people
beforehand if you are to work on their branch. Once you are done:

```
git commit -m "your additions"
git push hackaugusto travis_build
```

Congratulations, you have added to someone else's PR!
