#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : test_SMBSession_path_isdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 26 may 2024


from .common import CreateSMBSession, CustomTestCase


class test_SMBSession_path_isfile(CustomTestCase):
    
    title = "SMBSession.path_isfile()"

    def setUp(self):
        self.session = CreateSMBSession()

    def test_path_none(self):
        self.assertFalse(self.session.path_isfile(None), "Testing a None path")

    def test_path_empty(self):
        self.assertFalse(self.session.path_isfile(""), "Testing validity of path ''")

    def test_path_space(self):
        self.assertFalse(self.session.path_isfile(" "), "Testing validity of path ' '")

    def test_path_with_dot(self):
        self.assertFalse(self.session.path_isfile("."), "Testing validity of path '.'")

    def test_path_with_forward_slash(self):
        self.assertFalse(self.session.path_isfile("/"), "Testing validity of path '/'")

    def test_path_with_back_slash(self):
        self.assertFalse(self.session.path_isfile("\\"), "Testing validity of path '\\'")

    def test_path_existence(self):
        self.session.set_share("TestShare")
        self.session.set_cwd("path_isfile")
        path = "path_isfile\\a\\b\\file.txt"
        self.assertTrue(
            self.session.path_isfile(path),
            "Testing existence of file '%s' in share '%s'" % (path, self.session.smb_share)
        )
