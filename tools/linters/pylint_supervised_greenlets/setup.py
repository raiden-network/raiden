import setuptools

url = (
    'https://github.com/raiden-network/raiden'
    '/tree/master/tools/linters/pylint_supervised_greenlets'
)

setuptools.setup(
    name='pylint_supervised_greenlets',
    license='MIT',
    version='0.0.1',
    description='Flake8 checker to ensure all started greenlets are waited on',
    author='Brainbot Labs Est.',
    author_email='contact@brainbot.li',
    url=url,
    packages=[
        'pylint_supervised_greenlets',
    ],
    install_requires=[
        'pylint >= 2.1.0',
        'astroid >= 2.0.0',
    ],
    classifiers=[
        'Framework :: Pylint',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Quality Assurance',
    ],
)
