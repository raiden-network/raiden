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
	@echo "clean-truffle - remove 'truffle init' artifacts"
	@echo "build-truffle-container - build the truffle docker container"
	@echo "compile - run truffle compile"
	@echo "serve - run truffle serve"
	@echo "deploy - run truffle deploy"



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
	open htmlcov/index.html

docs:
	rm -f docs/raiden.rst
	rm -f docs/modules.rst
	sphinx-apidoc -o docs/ raiden
	$(MAKE) -C docs clean
	$(MAKE) -C docs html
	open docs/_build/html/index.html

release: clean
	python setup.py sdist upload
	python setup.py bdist_wheel upload

dist: clean
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

install: clean
	python setup.py install

# targets for truffle deployment
logging_settings = :info,contracts:debug
mkfile_root := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
dockerargs := --rm 
cmd := version
opts := 
call_truffle := docker run -it --user=$(process_user) -v $(mkfile_root)truffle:/code -v $(mkfile_root)raiden/smart_contracts:/code/contracts --net=host $(dockerargs) truffle $(cmd) $(opts)

clean-truffle:
	rm -rf truffle/app
	rm -rf truffle/contracts
	rm -rf truffle/environments
	rm -rf truffle/test
	rm -rf truffle/truffle.js

stop:
	killall hydrachain
	docker stop -t 0 truffleserver && docker rm truffleserver

build-truffle-container:
	cd truffle && docker build -t truffle .

blockchain:
	rm -f blockchain.log
	-(hydrachain -d $(shell mktemp -d) -l $(logging_settings) -c jsonrpc.corsdomain='http://localhost:8080' --log-file=blockchain.log runmultiple > /dev/null 2>&1 &)

serve: deploy
	@$(MAKE) run-truffle cmd=serve dockerargs="-d --name truffleserver"
	@echo "serving on http://localhost:8080 accounts are [ 0x8ed66d0dd4b88fb097a3a3c8c10175b8cadb1c66 0x2ca7fd47fc3c945a1f41fbc3f65c944df5a8f523 ]"

compile:
	@$(MAKE) run-truffle cmd=compile

build:
	@$(MAKE) run-truffle cmd=build

deploy:
	@$(MAKE) run-truffle cmd=deploy

run-truffle:
	$(call_truffle)
