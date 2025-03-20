#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : tree.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_tree(Command):
    name = "tree"
    description = "Displays a tree view of the remote directories."

    HELP = {
        "description": [
            description,
            "Syntax: 'tree [directory]'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('path', type=str, nargs='*', help='List of remote directories to display')
        return parser

    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return 

        if len(self.options.path) == 0:
            self.options.path = ['.']

        for path in self.options.path:
            interactive_shell.sessionsManager.current_session.tree(path=path)