#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lrmdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.CommandArgumentParser import CommandArgumentParser
import os
import shutil
from smbclientng.types.Command import Command
    

class Command_lrmdir(Command):
    name = "lrmdir"
    description = "Removes a local directory."

    HELP = {
        "description": [
            description, 
            "Syntax: 'lrmdir <directory>'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('path', type=str, nargs='?', help='List of local directories to remove')
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
                if os.path.isdir(s=path):
                    try:
                        shutil.rmtree(path=path)
                    except Exception as e:
                        interactive_shell.logger.error("Error removing directory '%s' : %s" % path)
                else:
                    interactive_shell.logger.error("Cannot delete '%s'. It is a file, use 'lrm <file>' instead." % path)
            else:
                interactive_shell.logger.error("Path '%s' does not exist." % path)