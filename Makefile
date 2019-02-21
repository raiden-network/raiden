.PHONY: clean-pyc clean-build docs clean

help:
	@echo "clean - remove all build, test, coverage and Python artifacts"
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "clean-test - remove test and coverage artifacts"
	@echo "lint - check style with flake8"
	@echo "mypy - check types with mypy (coverage in progress)"
	@echo "isort - use isort to fix import order"
	@echo "test - run tests quickly with the default Python"
	@echo "test-all - run tests on every Python version with tox"
	@echo "coverage - check code coverage quickly with the default Python"
	#@echo "docs - generate Sphinx HTML documentation, including API docs"
	#@echo "release - package and upload a release"
	#@echo "dist - package"
	#@echo "install - install the package to the active Python's site-packages"
	@echo "deploy - deploy contracts via rpc"



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
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test:
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/

ISORT_PARAMS = --ignore-whitespace --settings-path ./ --recursive raiden/ -sg */node_modules/*

lint:
	flake8 raiden/ tools/
	isort $(ISORT_PARAMS) --diff --check-only
	pylint --rcfile .pylint.rc raiden/
	python setup.py check --restructuredtext --strict

mypy:
	# We are starting small with a few files and directories here,
	# but mypy should run on the whole codebase soon.
	mypy raiden/transfer raiden/api raiden/messages.py raiden/blockchain \
	raiden/encoding raiden/storage raiden/network \
	--ignore-missing-imports | grep error > mypy-out.txt || true
	# Expecting status code 1 from `grep`, which indicates no match.
	# Again, we are starting small, detecting only errors related to
	# 'BlockNumber', 'Address', 'ChannelID' etc, but all mypy errors should be
	# detected soon.
	grep BlockNumber mypy-out.txt; [ $$? -eq 1 ]
	grep Address mypy-out.txt; [ $$? -eq 1 ]
	grep ChannelID mypy-out.txt; [ $$? -eq 1 ]
	grep BalanceProof mypy-out.txt; [ $$? -eq 1 ]
	grep SendSecret mypy-out.txt; [ $$? -eq 1 ]

isort:
	isort $(ISORT_PARAMS)

test:
	python setup.py test

test-all:
	tox

coverage:
	coverage run --source raiden setup.py test
	coverage report -m
	coverage html

docs:
	rm -f docs/raiden.rst
	rm -f docs/modules.rst
#     sphinx-apidoc -o docs/ raiden
	$(MAKE) -C docs clean
	$(MAKE) -C docs html


ARCHIVE_TAG_ARG=
ifdef ARCHIVE_TAG
ARCHIVE_TAG_ARG=--build-arg ARCHIVE_TAG=$(ARCHIVE_TAG)
else
ARCHIVE_TAG_ARG=--build-arg ARCHIVE_TAG=v$(shell python setup.py --version)
endif

# architecture needs to be asked in docker because docker can be run on remote host to create binary for different architectures
ARCHITECTURE_TAG=$(shell docker run --rm python:3.7 uname -m)

GITHUB_ACCESS_TOKEN_ARG=
ifdef GITHUB_ACCESS_TOKEN
GITHUB_ACCESS_TOKEN_ARG=--build-arg GITHUB_ACCESS_TOKEN_FRAGMENT=$(GITHUB_ACCESS_TOKEN)@
endif


bundle-docker:
	@docker build -t pyinstallerbuilder --build-arg GETH_URL_LINUX=$(GETH_URL_LINUX) --build-arg SOLC_URL_LINUX=$(SOLC_URL_LINUX) --build-arg ARCHITECTURE_TAG=$(ARCHITECTURE_TAG) $(ARCHIVE_TAG_ARG) $(GITHUB_ACCESS_TOKEN_ARG) -f docker/build.Dockerfile .
	-(docker rm builder)
	docker create --name builder pyinstallerbuilder
	mkdir -p dist/archive
	docker cp builder:/raiden/raiden-$(ARCHIVE_TAG)-linux-$(ARCHITECTURE_TAG).tar.gz dist/archive/raiden-$(ARCHIVE_TAG)-linux-$(ARCHITECTURE_TAG).tar.gz
	docker rm builder

bundle:
	pyinstaller --noconfirm --clean raiden.spec

release: clean
	python setup.py sdist upload
	python setup.py bdist_wheel upload

dist: clean
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

install: clean
	python setup.py install

logging_settings = :info,contracts:debug
mkfile_root := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

stop-geth:
	killall -15 geth

blockchain-geth:
	rm -f blockchain.log
	./tools/startcluster.py

deploy:
	./tools/deploy.py --keystore-path=${KEYSTORE}
