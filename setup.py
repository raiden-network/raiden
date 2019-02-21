#!/usr/bin/env python
from setuptools import find_packages, setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        raise SystemExit(errno)


with open('README.rst') as readme_file:
    readme = readme_file.read()


history = ''


with open('constraints.txt') as req_file:
    install_requires = list({
        requirement
        for requirement in req_file
        if requirement.strip() and not requirement.lstrip().startswith('#')
    })

test_requirements = []

# Do not edit: this is maintained by bumpversion (see .bumpversion_client.cfg)
version = '0.100.2'

setup(
    name='raiden',
    description='',
    long_description=readme + '\n\n' + history,
    author='Brainbot Labs Est.',
    author_email='contact@brainbot.li',
    url='https://github.com/raiden-network/raiden',
    packages=find_packages(),
    include_package_data=True,
    license='MIT',
    zip_safe=False,
    keywords='raiden',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
    ],
    cmdclass={
        'test': PyTest,
    },
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    install_requires=install_requires,
    tests_require=test_requirements,
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'raiden = raiden.__main__:main',
        ],
    },
)
