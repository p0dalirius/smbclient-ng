#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : head.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
from smbclientng.utils import resolve_remote_files
import charset_normalizer
from smbclientng.types.Command import Command   
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_head(Command):
    name = "head"
    description = "Get the first <n> lines of a remote file."

    HELP = {
        "description": [
            description, 
            "Syntax: 'head <file>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_file"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('-n', '--lines', type=int, default=10, help='Number of lines to display')
        parser.add_argument('files', nargs='*', help='Files or directories to get')
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
        
        if len(self.options.files) == 0:
            self.options.files = ['*']

        # Parse wildcards
        files_and_directories = resolve_remote_files(interactive_shell.sessionsManager.current_session, arguments)

        for path_to_file in files_and_directories:
            if interactive_shell.sessionsManager.current_session.path_isfile(pathFromRoot=path_to_file):
                # Read the file
                try:
                    rawcontents = interactive_shell.sessionsManager.current_session.read_file(path=path_to_file)

                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]

                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            lines = filecontent.split('\n')
                            if len(lines) > self.options.lines:
                                filecontent = '\n'.join(lines[:self.options.lines])
                            if len(files_and_directories) > 1:
                                interactive_shell.logger.print("\x1b[1;93m[>] %s\x1b[0m" % (path_to_file+' ').ljust(80,'='))
                            interactive_shell.logger.print(filecontent)

                        else:
                            interactive_shell.logger.error("[!] Could not detect charset of '%s'." % path_to_file)
                            
                except (SMBConnectionSessionError, SMB3SessionError) as e:
                    interactive_shell.logger.error("[!] SMB Error: %s" % e)
