#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : use.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed
from smbclientng.core.Command import Command

class Command_use(Command):
    HELP = {
        "description": [
            "Use a SMB share.", 
            "Syntax: 'use <sharename>'"
        ], 
        "subcommands": [],
        "autocomplete": ["share"]
    }

    @classmethod
    @command_arguments_required
    @active_smb_connection_needed
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : No
        
        sharename = arguments[0]

        # Reload the list of shares
        shares = interactive_shell.sessionsManager.current_session.list_shares()
        shares = [s.lower() for s in shares.keys()]

        if sharename.lower() in shares:
            interactive_shell.sessionsManager.current_session.set_share(sharename)
        else:
            interactive_shell.logger.error("No share named '%s' on '%s'" % (sharename, interactive_shell.sessionsManager.current_session.host))
