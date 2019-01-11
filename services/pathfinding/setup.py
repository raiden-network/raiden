#!/usr/bin/env python
"""The setup script."""

from setuptools import find_packages, setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

install_requires_replacements = {
    'git+https://github.com/matrix-org/matrix-python-sdk.git': 'matrix-client',
    'git+https://github.com/raiden-network/raiden-libs.git': 'raiden-libs',
    'git+https://github.com/raiden-network/raiden-contracts.git': 'raiden-contracts',
}

requirements = list(set(
    install_requires_replacements.get(requirement.strip(), requirement.strip())
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
            'pathfinding_service=pathfinding_service.cli:main',
        ],
    },
    install_requires=requirements,
    long_description=readme,
    include_package_data=True,
    keywords='pathfinding_service',
    name='pathfinding_service',
    packages=find_packages(include=['pathfinding_service']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/raiden-network/raiden-pathfinding-service',
    version='0.0.1',
    zip_safe=False,
)
