#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : reconnect.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025


HELP = {
    "description": [
        "Reconnect to the remote machine (useful if connection timed out).", 
        "Syntax: 'reconnect'"
    ], 
    "subcommands": [],
    "autocomplete": []
}


def command_reconnect(self, arguments: list[str], command: str):
    # Command arguments required   : No
    # Active SMB connection needed : No
    # SMB share needed             : No

    self.sessionsManager.current_session.ping_smb_session()
    if self.sessionsManager.current_session.connected:
        self.sessionsManager.current_session.close_smb_session()
        self.sessionsManager.current_session.init_smb_session()
    else:
        self.sessionsManager.current_session.init_smb_session()