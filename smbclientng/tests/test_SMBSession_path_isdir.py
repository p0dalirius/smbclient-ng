#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : test_SMBSession_path_isdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 26 may 2024


from .common import CreateSMBSession, CustomTestCase


class test_SMBSession_path_isdir(CustomTestCase):
    
    title = "SMBSession.path_isdir()"

    def setUp(self):
        self.session = CreateSMBSession()

    def test_path_none(self):
        self.assertFalse(self.session.path_isdir(None), "Testing a None path")

    def test_path_true_empty(self):
        self.assertTrue(self.session.path_isdir(""), "Testing valididty of path ''")

    def test_path_true_space(self):
        self.assertTrue(self.session.path_isdir(" "), "Testing valididty of path ' '")

    def test_path_true_with_dot(self):
        self.assertTrue(self.session.path_isdir("."), "Testing valididty of path '.'")

    def test_path_true_with_forward_slash(self):
        self.assertTrue(self.session.path_isdir("/"), "Testing valididty of path '/'")

    def test_path_true_with_back_slash(self):
        self.assertTrue(self.session.path_isdir("\\"), "Testing valididty of path '\\'")

    def test_path_existence(self):
        self.session.set_share("TestShare")
        self.session.set_cwd("path_isdir")
        path = "path_isdir\\a\\b"
        self.assertTrue(
            self.session.path_isdir(path),
            "Testing existence of path '%s' in share '%s'" % (path, self.session.smb_share)
        )