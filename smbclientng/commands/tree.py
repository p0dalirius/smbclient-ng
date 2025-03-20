#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : tree.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from smbclientng.types.Command import Command


class Command_tree(Command):
    name = "tree"
    description = "Displays a tree view of the remote directories."

    HELP = {
        "description": [
            description,
            "Syntax: 'tree [directory]'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
    # Command arguments required   : No
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

        if len(arguments) == 0:
            interactive_shell.sessionsManager.current_session.tree(path='.')
        else:
            interactive_shell.sessionsManager.current_session.tree(path=arguments[0])