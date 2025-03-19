#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : cd.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError


HELP = {
    "description": [
        "Change the current working directory.", 
        "Syntax: 'cd <directory>'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_directory"]
}


@command_arguments_required
@active_smb_connection_needed
@smb_share_is_set
def command_cd(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    try:
        self.sessionsManager.current_session.set_cwd(path=arguments[0])
    except (SMBConnectionSessionError, SMB3SessionError) as e:
        self.logger.error("[!] SMB Error: %s" % e)
