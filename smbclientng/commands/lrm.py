#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lrm.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_lrm(Command):
    name = "lrm"
    description = "Removes a local file."

    HELP = {
        "description": [description, "Syntax: 'lrm <file>'"],
        "subcommands": [],
        "autocomplete": ["local_file"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument(
            "path", type=str, nargs="+", help="List of local files to remove"
        )
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        for path in self.options.path:
            if os.path.exists(path):
                if not os.path.isdir(s=path):
                    try:
                        os.remove(path=path)
                    except Exception:
                        interactive_shell.logger.error(
                            "Error removing file '%s' : %s" % path
                        )
                else:
                    interactive_shell.logger.error(
                        "Cannot delete '%s'. It is a directory, use 'lrmdir <directory>' instead."
                        % path
                    )
            else:
                interactive_shell.logger.error("Path '%s' does not exist." % path)
