#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : mkdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_mkdir(Command):
    name = "mkdir"
    description = "Creates a new remote directory."

    HELP = {
        "description": [
            description, 
            "Syntax: 'mkdir <directory>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('path', type=str, nargs='*', help='List of remote directories to create')
        return parser

    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        self.options = self.processArguments(arguments=arguments)   
        if self.options is None:
            return 

        for path in self.options.path:
            try:
                interactive_shell.sessionsManager.current_session.mkdir(path=path)
            except Exception as err:
                interactive_shell.logger.print("Error creating directory %s: %s" % (path, err))
