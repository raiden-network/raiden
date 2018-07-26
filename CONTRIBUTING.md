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

If you experience a problem while using Raiden or want to request a feature
then you should open an issue against the repository. All issues should
contain:

**For Feature Requests:**
- A description of what you would like to see implemented
- An explanation of why you believe this would make a good addition to Raiden

**For Bugs:**
- A short description of the problem
- Detailed description of your system, raiden version, geth version, solidity version e.t.c.
- What was the exact unexpected thing that occured
- What you were expecting to happen instead

### Creating a Pull Request

If you have some coding abilities and would like to contribute to the actual
codebase of Raiden then you can open a Pull Request(PR) against the repository.

All PRs should be:
- Self-contained
- As short as possible and address a single issue or even a part of an issue.
  Consider breaking long PRs into smaller ones.

In order for a Pull Request to get merged into the main repository you should
have one approved review from one of the core developers of Raiden and also all
Continuous Integration tests should be passing and the CI build should be
green.

Additionally you need to sign the raiden project CLA (Contributor License
Agreement). Our CLA bot will help you with that after you created a pull
request. If you or your employer do not hold the whole copyright of the
authorship submitted we can not accept your contribution.

## Setup

### System dependencies

#### Debian/Ubuntu

Raiden requires Python >=3.6, Geth (Ethereum client), and the Solidity compiler
`solc`. The easiest way to get the last two is to add the official Ethereum ppa
to your repositories:

    sudo add-apt-repository -y ppa:ethereum/ethereum
    sudo apt-get update

Then simply install all required packages:

    sudo apt-get install build-essential git libffi-dev libgmp-dev libssl-dev \
      libtool pkg-config python-dev python-pip ethereum solc

For other ways to install `solc` or Geth see the official docs:

* http://solidity.readthedocs.io/en/latest/installing-solidity.html
* https://github.com/ethereum/go-ethereum/wiki/Building-Ethereum


### Raiden

#### Get the code

    git clone https://github.com/raiden-network/raiden.git
    cd raiden

#### Setup

First, create a `virtualenv` to keep your `pip` packages clean. If you haven't
already, install `virtualenv`:

    sudo pip install virtualenv

Create the virtual environment:

    virtualenv env

Install required packages:

    env/bin/pip install -r requirements-dev.txt -e .

#### Testing

Run the tests using

    env/bin/pytest raiden

Tests, especially integration tests, will take some time. If you want to run
single tests simply specify them on the command line, like so:

    env/bin/pytest raiden/tests/<path-to-test(s)>

## Development Guidelines

In this section we are going to describe the coding rules for contributing to
the raiden repository. All code you write should strive to comply with these
rules.

### Commiting Rules

For an exchaustive guide read [this](http://chris.beams.io/posts/git-commit/)
guide. It's all really good advice. Some rules that you should always follow though are:

- A commit title not exceeding 50 characters
- A blank line after the title (optional if there is no description)
- A description of what the commit did (optional if the commit is really small)

Why are these rules important? All tools that consume git repos and show you
information treat the first 80 characters as a title. Even Github itself does
this. And the git history looks really nice and neat if these simple rules are
followed.

### Encoding

Addresses should follow "sandwich encoding" so that each point of entry does
its own encoding into binary but the core programmatic API accepts only binary.
Thus we setup the following rules:

- Programmatic API should only expect binary and break if it accepts anything
  else. It should do type checking on its input and provide meaningful error
  for hex encoded addresses or length mismatch.
- All other places from which we receive addresses need to do their own
  encoding from whatever the input encoding is to binary. Such places are: CLI,
  Rest-API e.t.c.
- All modules which generate output to the outside world should also encode
  from binary to whatever the expected output encoding of that module is. Such
  places are stdout, communication with the ethereum node e.t.c.

### Coding Style

#### General Style

In this section we are going to see style rules that should be followed across all languages.

**Line breaks after operators**

For long expressions where we break the expression at the operators the line break should come **after** the operator and not before.

The following should be avoided:

```python
        participant1_amount = (
            participant1_state.deposit
            + participant2_state.transferred_amount
            - participant1_state.transferred_amount
        );
```

instead it should be:

```python
        participant1_amount = (
            participant1_state.deposit +
            participant2_state.transferred_amount -
            participant1_state.transferred_amount
        );
```

#### Python

Raiden is written in Python and we follow the official Python style guide
[PEP8](https://www.python.org/dev/peps/pep-0008/). It is highly recommended to
use the [flake8](https://pypi.python.org/pypi/flake8) tool in order to
automatically determine any and all style violations. The customizeable part of
flake can be seen in the [configuration file](setup.cfg). For all the rest
which are not configurable here is some general guidelines.

**Line Length**
Flake8 will warn you for 99 characters which is the hard limit on the max
length. Try not to go above it. We also have a soft limit on 80 characters but
that is not enforced and is there just to encourage short lines.

**Breaking function definitions when line is above 99 characters**

Always put each argument into its own line. Look at the following examples to
understand:

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
        argument7,
):
    pass
```

That means 8 spaces (double indentation after the opening parentheses of the function.

**Functions with type annotations**

When using type annotations the function should be just like in the above section but also include
the types of the arguments and the return type.

```python
def a(
        b: B,
        c: C,
) -> D:
    pass
```

**Docstrings**

For docstrings we follow [PEP 0257](https://www.python.org/dev/peps/pep-0257/#multi-line-docstrings).

A single line docstring should be like this:
```python
def a(
        b: B,
        c: C,
) -> D:
    """ Here be docs """
    pass
```

A multiline docstring should have a short title and then a body. So like this:

```python
def a(
        b: B,
        c: C,
) -> D:
    """ Function Title

    body comes
    here
    """
    pass
```

The closing quotes should be on their own line. If in doubt consult the PEP.

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

The only reason to use double quotes is to avoid escaping the single quote in a
string. So this is okay:

```python
s = "Augusto's computer is awesome"
```


**Naming Style**

Use [Snake Case](https://en.wikipedia.org/wiki/Snake_case) for variable and
function names and [Camel Case](https://en.wikipedia.org/wiki/Camel_case) for
class names.

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

We try to follow a consistent naming convention throughout the codebase to make
it easy for the reader of the code to understand what is going on. Thus we
introduce the following rules:

For addresses:

- `<name>_address_hex` for hex encoded addresses
- `<name>_address` for binary encoded addresses

Lists of objects:

- `<name>s`, e.g. `channels` for a list `Channel` object instances.

- to initialize an empty list use `list()` instead of `[]`. Note this is only
  for style consistency's sake and may change in the future as there [may
  be](https://stackoverflow.com/questions/5790860/and-vs-list-and-dict-which-is-better)
  a tiny change in performance.

Mappings/dicts:

If it is a simple one to one mapping

`<name>_to_<name>`, e.g. `tokenaddress_to_taskmanager`

If the mapped to object is a list then add an `s`

`<name>_to_<name>s`, e.g. `tokenaddress_to_taskmanagers = defaultdict(list())`

To initialize an empty dict use `dict()` instead of `{}`. Note this is only for
style consistency's sake and may change in the future as there [may
be](https://stackoverflow.com/questions/5790860/and-vs-list-and-dict-which-is-better)
a tiny change in performance.

Class attributes and functions:

All class members should be private by default and they should start with a leading `_`. Whatever is part of the interface of
the class should not have the leading underscore. The public interface of the class is what we should be testing in our tests
and it should be the only way other parts of the code use the class through.

Minimal Example:

```python

class Diary(object):

    def __init__(self, entries):
        self._entries = entries

    def entry(index):
        return _entries[index]

```

**NewTypes and type comparisons**

For often used types it makes sense to define new types using the `typing.NewType` function.
New type names should be capitalized.
```python
Address = NewType('Address', bytes)
```

These type definitions can not be used for type comparisons. To make this possible always
define a associated alias, which must start with `T_`.
```python
T_Address = bytes
```


#### Solidity

For solidity we generally follow the style guide as shown in the [solidity
documentation](http://solidity.readthedocs.io/en/develop/style-guide.html) with
a few notable exceptions:

**Variable Names**

All variable name should be in snake case, just like in python. Function names
on the other hand should be mixedCase. MixedCase is essentially like CamelCase
but with the initial letter being a small letter. This helps us to easily
determine which function calls are smart contract calls in the python code
side.

```js
function iDoSomething(uint awesome_argument) {
    doSomethingElse();
}
```


**Documentation**

Code should be documented. For docstrings the [Google
conventions](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html)
are used.


### Workflow

When developing a feature, or a bug fix you should always start by writting a
**test** for it, or by modifying existing tests to test for your feature. Once
you see that test failing you should implement the feature and confirm that all
your new tests pass.

Afterwards you should open a Pull Request from your fork or feature branch
against master. You will be given feedback from the core developers of raiden
and you should try to incorporate that feedback into your branch. Once you do
so and all tests pass your feature/fix will be merged.

#### Contributing to other people's PRs

If you are a core developer of Raiden with write privileges to the repository
then you can add commits or rebase to master any Pull Request by other people.

Let us take [this](https://github.com/raiden-network/raiden/pull/221) PR as an
example. The contributor has everything ready and all is looking good apart
from a minor glitch. You can wait until he fixes it himself but you can always
help him by contributing to his branch's PR:

```
git remote add hackaugusto git@github.com:hackaugusto/raiden.git
git fetch hackaugusto
git checkout travis_build
```

Right now you are working on the contributor's Pull Request. **Make sure** to
coordinate to avoid any conflicts and always warn people beforehand if you are
to work on their branch. Once you are done:

```
git commit -m "your additions"
git push hackaugusto travis_build
```

Congratulations, you have added to someone else's PR!

#### Integrating Pull Requests

When integrating a succesfull Pull Request into the codebase we have the option of using either a "Rebase and Merge" or to "Create a Merge commit". Unfortunately in Github the default option is to "Create a Merge commit". This is not our preferred option as
in this way we can't be sure that the result of the merge will also have all tests passing, since there may be other patches merged since the PR opened. But there are many PRs which we definitely know won't have any conflicts and for which enforcing rebase would make no sense and only waste our time. As such we provide the option to use both at our own discretion. So the general guidelines are:

- If there are patches that have been merged to master since the PR was opened, on top of which our current PR may have different behaviour then use **Rebase and Merge**.
- If there are patches that have been merged to master since the PR was opened which touch documentation, infrastucture or completely unrelated parts of the code then you can freely use **Create a Merge Commit** and save the time of rebasing.
