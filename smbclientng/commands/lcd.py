#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lcd.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
import os


class Command_lcd(Command):
    name = "lcd"
    description = "Changes the current local directory."

    HELP = {
        "description": [
            description,
            "Syntax: 'lcd <directory>'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('path', type=str, help='The local directory to change to')
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return 

        if os.path.exists(path=self.options.path):
            if os.path.isdir(s=self.options.path):
                os.chdir(path=self.options.path)
            else:
                interactive_shell.logger.error("Path '%s' is not a directory." % self.options.path)
        else:
            interactive_shell.logger.error("Directory '%s' does not exists." % self.options.path)