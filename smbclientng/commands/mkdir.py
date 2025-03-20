#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : mkdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from smbclientng.core.Command import Command


class Command_mkdir(Command):
    HELP = {
        "description": [
            "Creates a new remote directory.", 
            "Syntax: 'mkdir <directory>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    @classmethod
    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        interactive_shell.sessionsManager.current_session.mkdir(path=arguments[0])