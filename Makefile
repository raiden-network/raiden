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
	open htmlcov/index.html

docs:
	rm -f docs/raiden.rst
	rm -f docs/modules.rst
	sphinx-apidoc -o docs/ raiden
	$(MAKE) -C docs clean
	$(MAKE) -C docs html
	open docs/_build/html/index.html

bundle:
	docker build -t raidenbundler -f docker/build.Dockerfile docker
	-(docker rm bundler)
	docker run --name bundler --privileged -e ARCH=x86_64 -e APP=raiden -e LOWERAPP=raiden --workdir / --entrypoint /bin/bash raidenbundler -c 'source functions.sh && generate_appimage'
	mkdir -p dist
	docker cp bundler:/out/raiden--x86_64.AppImage dist/raiden--x86_64.AppImage
	docker rm bundler

test_bundle_docker := docker run --privileged --rm -v $(shell pwd)/dist:/data
test_bundle_exe := /data/raiden--x86_64.AppImage --help
test_bundle_test := grep -q "Usage: raiden"

test-bundle:
	${test_bundle_docker} base/archlinux \
		sh -c \
		'pacman -Syy && pacman --noconfirm -S fuse grep && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- success 'archlinux'
	${test_bundle_docker} ubuntu:14.04 \
		sh -c \
		'apt-get update && apt-get install -y fuse && cd /tmp/ && \
		apt-get download libglib2.0 && dpkg -i --force-all *.deb && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- success 'ubuntu:14.04'
	${test_bundle_docker} ubuntu:16.04 \
		sh -c \
		'apt-get update && apt-get install -y fuse && cd /tmp/ && \
		apt-get download libglib2.0 && dpkg -i --force-all *.deb && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- success 'ubuntu:16.04'
	${test_bundle_docker} ubuntu:16.10 \
		sh -c \
		'apt-get update && apt-get install -y fuse && cd /tmp/ && \
		apt-get download libglib2.0 && dpkg -i --force-all *.deb && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- success 'ubuntu:16.10'
	${test_bundle_docker} ubuntu:17.04 \
		sh -c \
		'apt-get update && apt-get install -y fuse && cd /tmp/ && \
		apt-get download libglib2.0 && dpkg -i --force-all *.deb && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- success 'ubuntu:17.04'
	${test_bundle_docker} debian:8 \
		sh -c \
		'apt-get update && apt-get install -y fuse && cd /tmp/ && \
		apt-get download libglib2.0 && dpkg -i --force-all *.deb && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- success 'debian:8'
	${test_bundle_docker} debian:9 \
		sh -c \
		'apt-get update && apt-get install -y fuse && cd /tmp/ && \
		apt-get download libglib2.0 && dpkg -i --force-all *.deb && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- success 'debian:9'
	${test_bundle_docker} centos:7 \
		sh -c \
		'yum install -y fuse-libs && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- success 'centos:7'

test-bundle-unsupported:
	# not yet supported (version `GLIBC_2.14' not found):
	! ${test_bundle_docker} centos:5 \
		sh -c \
		'yum install -y fuse-libs && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- failures for 'centos:5'
	! ${test_bundle_docker} centos:6 \
		sh -c \
		'yum install -y fuse-libs && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- failures for 'centos:6'
	! ${test_bundle_docker} debian:7 \
		sh -c \
		'apt-get update && apt-get install -y fuse && cd /tmp/ && \
		apt-get download libglib2.0 libpcre3 && dpkg -i --force-all *.deb && \
		${test_bundle_exe}' | ${test_bundle_test}
	# ^-- failures for 'debian:7'

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
