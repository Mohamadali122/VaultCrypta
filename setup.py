#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name="VaultCrypta",
    version="1.0.0",
    description="AES encrypted file processor with GZIP compression, real-time monitoring, and CLI support.",
    author="Mazio",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "watchdog",
        "python-dotenv",
        "tqdm"
    ],
    entry_points={
        'console_scripts': [
            'VaultCrypta=main:main'
        ],
    },
    python_requires='>=3.7',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
)