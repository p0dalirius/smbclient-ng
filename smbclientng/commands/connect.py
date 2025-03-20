#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : connect.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command


class Command_connect(Command):
    name = "connect"
    description = "Connect to the remote machine (useful if connection timed out)."

    HELP = {
        "description": [
            description, 
            "Syntax: 'connect'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }
    
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        interactive_shell.sessionsManager.current_session.ping_smb_session()