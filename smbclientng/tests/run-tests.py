#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024

from smbclientng.tests.test_SMBSession import test_SMBSession
from smbclientng.tests.test_SMBSession_path_isdir import test_SMBSession_path_isdir
from smbclientng.tests.test_SMBSession_path_isfile import test_SMBSession_path_isfile


__builtins__.print = lambda x:None


testCases = [
    test_SMBSession,
    test_SMBSession_path_isdir,
    test_SMBSession_path_isfile
]   


def main():
    for t in testCases:
        t().runAll()


if __name__ == "__main__":
    main()