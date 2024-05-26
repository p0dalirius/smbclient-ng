#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from smbclientng.core.SMBSession import SMBSession
import sys


class CustomTestCase(object):

    title = "CustomTestCase"

    def setUp(self):
        pass

    def assertFalse(self, value, message):
        self.__printTestResult(
            (value == False),
            message
        )

    def assertTrue(self, value, message):
        self.__printTestResult(
            (value == True),
            message
        )

    def assertIsNotNone(self, value, message):
        self.__printTestResult(
            (value is not None),
            message
        )
        
    def __printTestResult(self, testPassed, message):
        message = message + " \x1b[90m" + "─"*(70-len(message)) + "\x1b[0m"
        if testPassed:
            sys.stdout.write("  ├── %s \x1b[1;48;2;83;170;51;97m PASSED \x1b[0m\n" % message)
        else:
            sys.stdout.write("  ├── %s \x1b[1;48;2;233;61;3;97m FAILED \x1b[0m\n" % message)
        sys.stdout.flush()

    @classmethod
    def runAll(cls):
        sys.stdout.write("[>] \x1b[1m%s\x1b[0m\n" % cls.title)
        sys.stdout.flush()

        testCases = [f for f in dir(cls) if f.startswith('test_')]
        for fname in testCases:
            self = cls()
            self.setUp()
            getattr(self, fname)()


def CreateSMBSession():
    return SMBSession(
        address="10.0.0.201",
        domain="LAB",
        username="Administrator",
        password="Admin123!",
        lmhash="",
        nthash="",
        use_kerberos=False,
        debug=True
    )

