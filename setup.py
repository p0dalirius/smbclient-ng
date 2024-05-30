#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : setup.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Jul 2022

import setuptools

long_description = """"""

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [x.strip() for x in f.readlines()]

setuptools.setup(
    name="smbclientng",
    version="1.1",
    description="smbclient-ng, a fast and user friendly way to interact with SMB shares.",
    url="https://github.com/p0dalirius/smbclient-ng",
    author="Podalirius",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email="podalirius@protonmail.com",
    packages=["smbclientng", "smbclientng.core", "smbclientng.modules", "smbclientng.tests"],
    package_data={'smbclientng': ['smbclientng/']},
    include_package_data=True,
    license="GPL3",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=requirements,
    entry_points={
        'console_scripts': ['smbclientng=smbclientng.__main__:main']
    }
)
