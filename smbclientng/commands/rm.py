#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : rm.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import ntpath    
from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_rm(Command):
    name = "rm"
    description = "Removes a remote file."

    HELP = {
        "description": [
            description,
            "Syntax: 'rm <remote_file>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_file"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('path', type=str, nargs='*', help='List of remote files to remove')
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

        for path_to_file in self.options.path:
            # Check if the path is absolute
            # Fullpath is required to check if path is a file
            if ntpath.isabs(path_to_file):
                full_path = ntpath.normpath(path_to_file)
            else:
                # Relative path, construct full path
                full_path = ntpath.normpath(ntpath.join(interactive_shell.sessionsManager.current_session.smb_cwd, path_to_file))
            # Wildcard handling
            if '*' in path_to_file:
                interactive_shell.sessionsManager.current_session.rm(path=path_to_file)
            # File
            elif interactive_shell.sessionsManager.current_session.path_exists(path_to_file):
                if interactive_shell.sessionsManager.current_session.path_isfile(full_path):
                    try:
                        interactive_shell.sessionsManager.current_session.rm(path=path_to_file)
                    except Exception as e:
                        interactive_shell.logger.error("Error removing file '%s' : %s" % path_to_file)
                else:
                    interactive_shell.logger.error("Cannot delete '%s': This is a directory, use 'rmdir <directory>' instead." % path_to_file)
            # File does not exist
            else:
                interactive_shell.logger.error("Remote file '%s' does not exist." % path_to_file)