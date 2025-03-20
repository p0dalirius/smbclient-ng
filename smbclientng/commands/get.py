#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : get.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import argparse
import traceback
from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
from smbclientng.utils.utils import resolve_remote_files
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_get(Command):
    name = "get"
    description = "Get a remote file."

    HELP = {
        "description": [
            description,
        ],
        "subcommands": [],
        "autocomplete": ["remote_file"]
    }

    def setupParser(self) -> argparse.ArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument("-r", "--recursive", dest='recursive', action='store_true', default=False, help='Recursively get files')
        parser.add_argument("--dont-keep-remote-path", dest='dont_keep_remote_path', action='store_true', default=False, help='Do not keep the remote path')
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
        files_and_directories = resolve_remote_files(interactive_shell.sessionsManager.current_session, self.options.files)

        # Download files/directories
        for remotepath in files_and_directories:
            try:
                interactive_shell.sessionsManager.current_session.get_file(
                    path=remotepath,
                    keepRemotePath=(not self.options.dont_keep_remote_path),
                    is_recursive=self.options.recursive
                )
            except (SMBConnectionSessionError, SMB3SessionError) as e:
                if interactive_shell.config.debug:
                    traceback.print_exc()
                interactive_shell.logger.error("[!] SMB Error: %s" % e)
