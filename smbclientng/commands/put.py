#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : put.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
from smbclientng.utils import resolve_local_files
import os
from smbclientng.types.Command import Command


class Command_put(Command):
    name = "put"
    description = "Put a local file or directory in a remote directory."

    HELP = {
        "description": [
            description, 
            "Syntax: 'put [-r] <directory or file>'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_file"]
    }
        
    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes
        
        is_recursive = False
        while '-r' in arguments:
            is_recursive = True
            arguments.remove('-r')

        # This is the usecase of 'put -r' with no other argument
        if len(arguments) == 0:
            arguments = ['*']

        # Parse wildcards
        files_and_directories = resolve_local_files(arguments)

        # 
        for localpath in files_and_directories:
            try:
                interactive_shell.logger.print(localpath)
                if is_recursive and os.path.isdir(s=localpath):
                    # Put files recursively
                    interactive_shell.sessionsManager.current_session.put_file_recursively(localpath=localpath)
                else:
                    # Put this single file
                    interactive_shell.sessionsManager.current_session.put_file(localpath=localpath)
            except (SMBConnectionSessionError, SMB3SessionError) as e:
                interactive_shell.logger.error("[!] SMB Error: %s" % e)