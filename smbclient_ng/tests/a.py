#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : .py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


import unittest
from smbclient_ng.core.SMBSession import SMBSession


class TestSMBSession(unittest.TestCase):
    def setUp(self):
        self.session = SMBSession(
            address="192.168.1.1",
            domain="EXAMPLE",
            username="user",
            password="password",
            lmhash="",
            nthash="",
            use_kerberos=False,
            debug=True
        )

    def test_initialization(self):
        self.assertIsNotNone(self.session)
        self.assertEqual(self.session.address, "192.168.1.1")
        self.assertEqual(self.session.domain, "EXAMPLE")
        self.assertEqual(self.session.username, "user")
        self.assertEqual(self.session.password, "password")
        self.assertFalse(self.session.use_kerberos)
        self.assertTrue(self.session.debug)

    def test_connection_status(self):
        self.assertFalse(self.session.connected, "Session should not be connected initially")

    def test_set_share(self):
        with self.assertRaises(ValueError):
            self.session.set_share(None)
        self.session.set_share("SHARE")
        self.assertEqual(self.session.smb_share, "SHARE")

    def test_set_cwd(self):
        self.session.set_cwd("/test/path")
        self.assertEqual(self.session.smb_cwd, "/test/path")

if __name__ == '__main__':
    unittest.main()
