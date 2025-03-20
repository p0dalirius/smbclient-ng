#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : reset.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import sys
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_reset(Command):
    name = "reset"
    description = "Reset the TTY output, useful if it was broken after printing a binary file on stdout."

    HELP = {
        "description": [
            description,
            "Syntax: 'reset'"
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
        sys.stdout.write('\x1b[?25h') # Sets the cursor to on
        sys.stdout.write('\x1b[v')  
        sys.stdout.write('\x1b[o') # Reset
        sys.stdout.flush()