#!/usr/bin/env python

from setuptools import setup

setup(
    name='encx',
    version='0.2',
    description='Encryption CLI tool and implementation of the encx file format.',
    author='KJ',
    author_email='jdotpy@users.noreply.github.com',
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
