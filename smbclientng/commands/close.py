#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : close.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_close(Command):
    name = "close"
    description = "Closes the SMB connection to the remote machine."

    HELP = {
        "description": [
            description, 
            "Syntax: 'close'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return 

        interactive_shell.sessionsManager.current_session.ping_smb_session()
        if interactive_shell.sessionsManager.current_session.connected:
            interactive_shell.sessionsManager.current_session.close_smb_session()