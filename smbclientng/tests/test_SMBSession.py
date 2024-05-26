#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : test_SMBSession.py
# Author             : Podalirius (@podalirius_)
# Date created       : 26 may 2024


from .common import CreateSMBSession, CustomTestCase


class test_SMBSession(CustomTestCase):

    title = "SMBSession()"

    def test_initialization(self):
        session = CreateSMBSession()
        self.assertIsNotNone(session, "Correct SMB Session initialization")

    def test_connection_status(self):
        session = CreateSMBSession()
        self.assertFalse(session.connected, "Session should not be connected initially")

