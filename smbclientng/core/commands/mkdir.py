#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : mkdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set


HELP = {
    "description": [
        "Creates a new remote directory.", 
        "Syntax: 'mkdir <directory>'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_directory"]
}


@command_arguments_required
@active_smb_connection_needed
@smb_share_is_set
def command_mkdir(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    self.sessionsManager.current_session.mkdir(path=arguments[0])