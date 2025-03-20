#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : sessions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_sessions(Command):
    name = "sessions"
    description = "Manage the SMB sessions."

    HELP = {
        "description": [
            description, 
            "Syntax: 'sessions [access|create|delete|execute|list]'"
        ], 
        "subcommands": ["create", "delete", "execute", "interact", "list"],
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

        interactive_shell.sessionsManager.process_command_line(arguments)