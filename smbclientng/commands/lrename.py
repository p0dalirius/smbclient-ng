#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lrename.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_lrename(Command):
    name = "lrename"
    description = "Renames a local file."

    HELP = {
        "description": [description, "Syntax: 'lrename <oldfilename> <newfilename>'"],
        "subcommands": [],
        "autocomplete": ["local_file"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument("oldfile", type=str, help="The old local file")
        parser.add_argument("newfile", type=str, help="The new local file")
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        os.rename(src=self.options.oldfile, dst=self.options.newfile)
