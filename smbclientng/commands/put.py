#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : put.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os

from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError as SMBConnectionSessionError

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.utils import resolve_local_files
from smbclientng.utils.decorator import (active_smb_connection_needed,
                                         smb_share_is_set)


class Command_put(Command):
    name = "put"
    description = "Put a local file or directory in a remote directory."

    HELP = {
        "description": [description, "Syntax: 'put [-r] <directory or file>'"],
        "subcommands": [],
        "autocomplete": ["local_file"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument(
            "path",
            type=str,
            nargs="*",
            help="List of local files or directories to put",
        )
        parser.add_argument(
            "-r",
            "--recursive",
            action="store_true",
            help="Put files from local path recursively",
        )
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

        if len(self.options.path) == 0:
            self.options.path = ["*"]

        # Parse wildcards
        files_and_directories = resolve_local_files(self.options.path)

        # If nothing matched, report it clearly
        if len(files_and_directories) == 0:
            interactive_shell.logger.error("[!] No local files matched the provided path(s).")
            return

        for localpath in files_and_directories:
            try:
                # Missing local path
                if not os.path.exists(localpath):
                    interactive_shell.logger.error(
                        "[!] Local path '%s' does not exist." % localpath
                    )
                    continue

                # Directory handling
                if self.options.recursive and os.path.isdir(localpath):
                    # Put files recursively
                    interactive_shell.sessionsManager.current_session.put_file_recursively(
                        localpath=localpath
                    )
                elif os.path.isdir(localpath):
                    interactive_shell.logger.error(
                        "[!] Local path '%s' is a directory, use the -r option to recursively put directories" % localpath
                    )
                else:
                    # Put this single file
                    interactive_shell.sessionsManager.current_session.put_file(
                        localpath=localpath
                    )
            except (SMBConnectionSessionError, SMB3SessionError) as e:
                interactive_shell.logger.error("[!] SMB Error: %s" % e)
