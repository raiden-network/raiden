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
	flake8 raiden/ tools/
	isort --ignore-whitespace --settings-path ./ --check-only --recursive --diff raiden/ -sg */node_modules/*
	pylint --rcfile .pylint.rc raiden/
	python setup.py check --restructuredtext --strict

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

ARCHIVE_TAG?=master

GITHUB_ACCESS_TOKEN_ARG=
ifdef GITHUB_ACCESS_TOKEN
GITHUB_ACCESS_TOKEN_ARG=--build-arg GITHUB_ACCESS_TOKEN_FRAGMENT=$(GITHUB_ACCESS_TOKEN)@
endif


bundle-docker:
	# Hide command echo to prevent leaking GITHUB_ACCESS_TOKEN in Travis logs
	@docker build -t pyinstallerbuilder --build-arg GETH_URL_LINUX=$(GETH_URL_LINUX) --build-arg SOLC_URL_LINUX=$(SOLC_URL_LINUX) --build-arg ARCHIVE_TAG=$(ARCHIVE_TAG) $(GITHUB_ACCESS_TOKEN_ARG) -f docker/build.Dockerfile .
	-(docker rm builder)
	docker create --name builder pyinstallerbuilder
	mkdir -p build/archive
	docker cp builder:/raiden/raiden-$(ARCHIVE_TAG)-linux.tar.gz build/archive/raiden-$(ARCHIVE_TAG)-linux.tar.gz
	docker rm builder

bundle:
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

deploy:
	./tools/deploy.py --keystore-path=${KEYSTORE}
