#!/usr/bin/env python3

from distutils.core import setup

setup(
    name='encx',
    version='0.1',
    description='Encryption CLI and implementation of the encx file format.',
    author='KJ',
    author_email='<redacted>',
    url='<TBD>',
    packages=[
        'encx',
    ],
    install_requires=[
        'pycrypto'
    ],
    scripts=[
        'bin/encrypt.py',
        'bin/decrypt.py',
        'bin/keygen.py',
    ],
)
