#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : get.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
import traceback
from smbclientng.utils.utils import resolve_remote_files


HELP = {
    "description": [
        "Get a remote file.",
        "Syntax: 'get [-r] [-k] <directory or file>'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_file"]
}


@command_arguments_required
@active_smb_connection_needed
@smb_share_is_set
def command_get(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    is_recursive = False
    keep_remote_path = False  
    # Parse '-r' option
    while '-r' in arguments:
        is_recursive = True
        arguments.remove('-r')
    
    # Parse '-k' option for keepRemotePath if you have it
    while '-k' in arguments:
        keep_remote_path = True
        arguments.remove('-k')

    # Handle 'get -r' with no other argument
    if len(arguments) == 0:
        arguments = ['*']

    # Parse wildcards
    files_and_directories = resolve_remote_files(self.sessionsManager.current_session, arguments)

    # Download files/directories
    for remotepath in files_and_directories:
        try:
            self.sessionsManager.current_session.get_file(
                path=remotepath,
                keepRemotePath=keep_remote_path,
                is_recursive=is_recursive
            )
        except (SMBConnectionSessionError, SMB3SessionError) as e:
            if self.config.debug:
                traceback.print_exc()
            self.logger.error("[!] SMB Error: %s" % e)
