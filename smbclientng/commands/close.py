#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : close.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025


HELP = {
    "description": [
        "Closes the SMB connection to the remote machine.", 
        "Syntax: 'close'"
    ], 
    "subcommands": [],
    "autocomplete": []
}


def command_close(self, arguments: list[str], command: str):
    # Command arguments required   : No
    # Active SMB connection needed : No
    # SMB share needed             : No

    self.sessionsManager.current_session.ping_smb_session()
    if self.sessionsManager.current_session.connected:
        self.sessionsManager.current_session.close_smb_session()