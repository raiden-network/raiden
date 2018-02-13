.PHONY: clean-pyc clean-build docs clean

help:
	@echo "clean - remove all build, test, coverage and Python artifacts"
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "clean-test - remove test and coverage artifacts"
	@echo "lint - check style with flake8"
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

lint:
	flake8 raiden tests

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

RAIDENVERSION?=master
GETH_URL_LINUX?='https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-1.7.3-4bb3c89d.tar.gz'
SOLC_URL_LINUX?='https://github.com/ethereum/solidity/releases/download/v0.4.18/solc-static-linux'

bundle:
	docker build -t pyinstallerbuilder --build-arg GETH_URL_LINUX=$(GETH_URL_LINUX) --build-arg SOLC_URL_LINUX=$(SOLC_URL_LINUX) --build-arg RAIDENVERSION=$(RAIDENVERSION) -f docker/build.Dockerfile docker
	-(docker rm builder)
	docker create --name builder pyinstallerbuilder
	docker cp builder:/raiden/raiden-$(RAIDENVERSION).tar.gz dist/raiden-$(RAIDENVERSION).tar.gz
	docker rm builder

test_bundle_docker := docker run --privileged --rm -v $(shell pwd)/dist:/data
test_bundle_exe := /data/raiden--x86_64.AppImage --help
test_bundle_test := grep -q "Usage: raiden"

pyibundle:
	python setup.py compile_contracts
	python setup.py compile_webui
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

deploy: compile
	./tools/deploy.py
