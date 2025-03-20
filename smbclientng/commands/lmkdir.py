#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lmkdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_lmkdir(Command):
    name = "lmkdir"
    description = "Creates a new local directory."

    HELP = {
        "description": [
            description,
            "Syntax: 'lmkdir <directory>'"
        ],
        "subcommands": [],
        "autocomplete": ["local_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('path', type=str, nargs='+', help='List of local directories to create')
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return 

        for path in self.options.path:
            if os.path.sep in path:
                path = path.strip(os.path.sep).split(os.path.sep)
            else:
                path = [path]

            # Create each dir in the path
            for depth in range(1, len(path)+1):
                tmp_path = os.path.sep.join(path[:depth])
                if not os.path.exists(tmp_path):
                    os.mkdir(path=tmp_path)