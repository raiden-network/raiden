#!/usr/bin/env python
import os
import re
from typing import List

from setuptools import find_packages, setup
from setuptools.command.egg_info import egg_info
from setuptools.command.test import test as TestCommand

REQ_REPLACE = {re.compile(r"git\+https://github.com/(\w|-)+/raiden.git@.*"): "raiden"}


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args: List[str] = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest

        errno = pytest.main(self.test_args)
        raise SystemExit(errno)


class EggInfo(egg_info):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # FFS, setuptools_scm forcibly includes all files under version control into the sdist
        # package, ignoring `MANIFEST.in` and `find_packages`.
        # See https://github.com/pypa/setuptools_scm/issues/190
        # We 'fix' this by replacing the `find_files` function with a dummy one.
        # The reason this is done here and not on the top level is that setuptools_scm is a
        # setup time requirement so it may not have been installed when this setup.py is initially
        # executed.
        try:
            import setuptools_scm.integration

            setuptools_scm.integration.find_files = lambda _: []
        except ImportError:
            pass


with open("README.md") as readme_file:
    readme = readme_file.read()


history = ""


def read_requirements(path: str) -> List[str]:
    """Read requirements, skip comments, modify git dependencies

    setup.py does not support git dependencies, so we change those to simple package names, here.
    This only leads to the correct versions in the installation because we
    always use pip to install from the requirements file before setup.py gets
    executed. Cleaner solutions wanted!
    """
    assert os.path.isfile(path), "Missing requirements file"
    ret = []
    with open(path) as requirements:
        for line in requirements.readlines():
            line = line.strip()
            if line and line[0] in ("#", "-"):
                continue
            for regex, replacement in REQ_REPLACE.items():
                if regex.match(line):
                    line = replacement
            ret.append(line)

    return ret


test_requirements: List[str] = []

setup(
    name="raiden",
    description="",
    long_description=readme + "\n\n" + history,
    author="Brainbot Labs Est.",
    author_email="contact@brainbot.li",
    url="https://github.com/raiden-network/raiden",
    packages=find_packages(include=("raiden", "raiden.*")),
    package_data={"raiden": ["py.typed"]},
    license="MIT",
    zip_safe=False,
    include_package_data=True,
    long_description_content_type="text/markdown",
    keywords="raiden",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    cmdclass={"test": PyTest, "egg_info": EggInfo},
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=read_requirements("requirements/requirements.txt"),
    tests_require=test_requirements,
    python_requires=">=3.7",
    entry_points={"console_scripts": ["raiden = raiden.__main__:main"]},
)
