#!/usr/bin/env python3
from os import environ
from setuptools import setup, find_packages
from setup_requires import runtime_requires, testing_requires

VERSION = '0.0.1'
DESCRIPTION = 'A place to keep and re-display Google Authenticator QR codes'
LONG_DESCRIPTION = 'A package that makes it easy to store and display QR codes for re-use. Codes are stored in an encrypted file using a password of your choice.'

requires = runtime_requires
if environ.get('_TESTING', "").lower() == 'true':
    requires += testing_requires

setup(
    name="qr",
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    author="Jason Milen",
    author_email="jpmilen@gmail.com",
    license='MIT',
    packages=find_packages(),
    entry_points = {
        'console_scripts': [
            'qrcodes=authentication_qr_keeper.qr:main',
        ],
    },
    scripts=[
        'scripts/decrypt-file.sh',
        'scripts/edit-encrypted-file.sh',
        'scripts/encrypt-file.sh',
    ],
    install_requires=requires,
    keywords='conversion',
    classifiers= [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        'License :: OSI Approved :: MIT License',
        "Programming Language :: Python :: 3",
    ]
)