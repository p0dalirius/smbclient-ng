#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : reconnect.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.core.Command import Command


class Command_reconnect(Command):
    HELP = {
        "description": [
            "Reconnect to the remote machine (useful if connection timed out).", 
            "Syntax: 'reconnect'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        interactive_shell.sessionsManager.current_session.ping_smb_session()
        if interactive_shell.sessionsManager.current_session.connected:
            interactive_shell.sessionsManager.current_session.close_smb_session()
            interactive_shell.sessionsManager.current_session.init_smb_session()
        else:
            interactive_shell.sessionsManager.current_session.init_smb_session()