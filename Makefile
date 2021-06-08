.PHONY: clean-pyc clean-build docs clean

help:
	@echo "clean - remove all build, test, coverage and Python artifacts"
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "clean-test - remove test and coverage artifacts"
	@echo "-"
	@echo "lint - run all checks (style, mypy, etc.)"
	@echo "mypy - check types with mypy (coverage in progress)"
	@echo "mypy-all - Run mypy without filters and report remaining issue count"
	@echo "format - run isort and black"
	@echo "isort - use isort to fix import order"
	@echo "black - reformat code with black"
	@echo "test - run tests quickly with the default Python"
	@echo "coverage - check code coverage quickly with the default Python"
	@echo "-"
	@echo "install - install Raiden and runtime requirements into the active virtualenv"
	@echo "install-dev - install Raiden in editable mode and development dependencies into the active virtualenv"
	@echo "-"
	@echo "bundle - create standalone executable with PyInstaller"
	@echo "bundle-docker - create standalone executable with PyInstaller via a docker container"
	@echo "docs - generate Sphinx HTML documentation, including API docs"


clean: clean-build clean-pyc clean-test

clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test:
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/

# CircleCI always reports 36 CPUs, force tools to use the actual number
JOBS_ARG=
ifdef CIRCLECI
JOBS_ARG=--jobs=8
endif
LINT_PATHS = raiden/ tools/ setup.py conftest.py
ISORT_PARAMS = --ignore-whitespace --settings-path ./ --skip-glob '*/node_modules/*' $(LINT_PATHS)

lint: ISORT_CHECK_PARAMS := --diff --check-only
lint: BLACK_CHECK_PARAMS := --check --diff
lint: format flake8 mypy pylint shellcheck check-pre-commit

mypy:
	mypy raiden tools

mypy-all:
	# Be aware, that we currently ignore all mypy errors in `raiden.tests.*` through `setup.cfg`.
	# Remaining errors in tests:
	mypy --config-file /dev/null raiden --ignore-missing-imports | grep error | wc -l

flake8:
	flake8 $(JOBS_ARG) $(LINT_PATHS)

pylint:
	pylint $(JOBS_ARG) $(LINT_PATHS)

isort:
	isort $(JOBS_ARG) $(ISORT_PARAMS) $(ISORT_CHECK_PARAMS)

black:
	black $(BLACK_CHECK_PARAMS) $(LINT_PATHS)

shellcheck:
ifeq (, $(shell command -v shellcheck 2> /dev/null))
	@echo "Shellcheck isn't installed. Shell scripts won't be linted!"
else
	find tools/ .circleci/ -name "*.sh" -print0 | xargs -0 shellcheck -x
	shellcheck requirements/deps
endif

check-pre-commit:
	python tools/pre-commit/pre-commit-check-versions.py

format: isort black

test:
	pytest -n auto -v raiden/tests

coverage:
	coverage run --source raiden pytest -v raiden/tests
	coverage report -m
	coverage html

docs:
	rm -f docs/raiden.rst
	rm -f docs/modules.rst
#     sphinx-apidoc -o docs/ raiden
	$(MAKE) -C docs clean
	$(MAKE) -C docs html


install: check-pip-tools clean-pyc
	cd requirements; pip-sync requirements.txt _raiden.txt

install-dev: check-pip-tools clean-pyc osx-detect-proper-python
# Remove extras from requirements to produce a valid constraints file.
# See: https://github.com/pypa/pip/issues/9209
	@sed -e 's/\[[^]]*\]//g' requirements/requirements-dev.txt > requirements/constraints-dev.txt
	@touch requirements/requirements-local.txt
	cd requirements; pip-sync requirements-dev.txt _raiden-dev.txt
	pip install -c requirements/constraints-dev.txt -r requirements/requirements-local.txt
	@rm requirements/constraints-dev.txt

osx-detect-proper-python:
ifeq ($(shell uname -s),Darwin)
	@python -c 'import time; time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)' > /dev/null 2>&1 || (echo "Not supported python version. Read https://raiden-network.readthedocs.io/en/latest/macos_install_guide.html#macos-development-setup for details."; exit 1)
endif

GITHUB_ACCESS_TOKEN_ARG=
ifdef GITHUB_ACCESS_TOKEN
GITHUB_ACCESS_TOKEN_ARG=--build-arg GITHUB_ACCESS_TOKEN_FRAGMENT=$(GITHUB_ACCESS_TOKEN)@
endif

# architecture needs to be asked in docker because docker can be run on remote host to create binary for different architectures
bundle-docker: ARCHITECTURE_TAG = $(shell docker run --rm python:3.7 uname -m)
bundle-docker: ARCHIVE_TAG ?= v$(shell python setup.py --version)
bundle-docker:
	docker build -t pyinstallerbuilder --build-arg ARCHITECTURE_TAG=$(ARCHITECTURE_TAG) --build-arg ARCHIVE_TAG=$(ARCHIVE_TAG) $(GITHUB_ACCESS_TOKEN_ARG) -f docker/build.Dockerfile .
	-(docker rm builder)
	docker create --name builder pyinstallerbuilder
	mkdir -p dist/archive
	docker cp builder:/raiden/raiden-$(ARCHIVE_TAG)-linux-$(ARCHITECTURE_TAG).tar.gz dist/archive/raiden-$(ARCHIVE_TAG)-linux-$(ARCHITECTURE_TAG).tar.gz
	docker rm builder

bundle:
	pyinstaller --noconfirm --clean raiden.spec


check-venv:
	@python3 -c 'import sys; sys.exit(not (hasattr(sys, "real_prefix") or sys.base_prefix != sys.prefix))' \
		|| (echo "It appears you're not working inside a venv / virtualenv\nIt's strongly recommended to install raiden into a virtual environment.\nSee the documentation for more details."; exit 1)

# Ensure pip-tools is installed
check-pip-tools: check-venv
	@command -v pip-compile > /dev/null 2>&1 || (echo "pip-tools is required. Installing." && python3 -m pip install $(shell grep pip-tools== requirements/requirements-dev.txt))
