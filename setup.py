#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

requirements = list(set(
    requirement
    for requirement in open('requirements.txt') if not requirement.lstrip().startswith('#')
))

setup_requirements = ['pytest-runner', ]

test_requirements = ['pytest', ]

setup(
    author="Brainbot Labs Est.",
    author_email='contact@brainbot.li',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    description="Pathfinding service for the Raiden Network",
    entry_points={
        'console_scripts': [
            'pathfinder=pathfinder.cli:main',
        ],
    },
    install_requires=requirements,
    long_description=readme,
    include_package_data=True,
    keywords='pathfinder',
    name='pathfinder',
    packages=find_packages(include=['pathfinder']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/raiden-network/raiden-pathfinding-service',
    version='0.0.1',
    zip_safe=False,
)
