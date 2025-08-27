#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lpwd.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_lpwd(Command):
    name = "lpwd"
    description = "Shows the current local directory."

    HELP = {
        "description": [description, "Syntax: 'lpwd'"],
        "subcommands": [],
        "autocomplete": [],
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

        interactive_shell.logger.print(os.getcwd())
