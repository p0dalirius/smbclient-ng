#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ls.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.utils import resolve_remote_files, windows_ls_entry
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.decorator import smb_share_is_set


class Command_ls(Command):
    name = "ls"
    description = "List the contents of the current remote working directory."

    HELP = {
        "description": [
            description, 
            "Syntax: 'ls'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('path', type=str, nargs='*', help='List of remote directories to list')
        return parser

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
            if len(self.options.path) > 1:
                interactive_shell.logger.print("%s:" % path)

            if interactive_shell.sessionsManager.current_session.path_isdir(pathFromRoot=path):
                # Read the files
                directory_contents = interactive_shell.sessionsManager.current_session.list_contents(path=path)
            else:
                entry = interactive_shell.sessionsManager.current_session.get_entry(path=path)
                if entry is not None:
                    directory_contents = {entry.get_longname(): entry}
                else:
                    directory_contents = {}

            for longname in sorted(directory_contents.keys(), key=lambda x:x.lower()):
                interactive_shell.logger.print(windows_ls_entry(directory_contents[longname], interactive_shell.config))

            if len(arguments) > 1:
                interactive_shell.logger.print()