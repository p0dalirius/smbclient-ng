#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : connect.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025


HELP = {
    "description": [
        "Connect to the remote machine (useful if connection timed out).", 
        "Syntax: 'connect'"
    ], 
    "subcommands": [],
    "autocomplete": []
}


def command_connect(self, arguments: list[str], command: str):
    # Command arguments required   : No
    # Active SMB connection needed : No
    # SMB share needed             : No

    self.sessionsManager.current_session.ping_smb_session()