#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ltree.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.utils import local_tree
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_ltree(Command):
    name = "ltree"
    description = "Displays a tree view of the local directories."  

    HELP = {
        "description": [
            description,
            "Syntax: 'ltree [directory]'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_directory"]
    }
    
    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('path', type=str, nargs='*', help='List of local directories to list')
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return 

        if len(self.options.path) == 0:
            self.options.path = ['.']

        for path in self.options.path:
            local_tree(path=path, config=interactive_shell.config)
