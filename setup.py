#!/usr/bin/env python3

from distutils.core import setup

setup(
    name='encx',
    version='0.2',
    description='Encryption CLI tool and implementation of the encx file format.',
    author='KJ',
    author_email='<redacted>',
    url='https://github.com/jdotpy/encx',
    packages=[
        'encxlib',
    ],
    install_requires=[
        'cryptography',
        'pyyaml',
    ],
    scripts=[
        'bin/encx',
    ],
)
