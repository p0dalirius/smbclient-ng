#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : use.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed


HELP = {
    "description": [
        "Use a SMB share.", 
        "Syntax: 'use <sharename>'"
    ], 
    "subcommands": [],
    "autocomplete": ["share"]
}


@command_arguments_required
@active_smb_connection_needed
def command_use(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : No
    
    sharename = arguments[0]

    # Reload the list of shares
    shares = self.sessionsManager.current_session.list_shares()
    shares = [s.lower() for s in shares.keys()]

    if sharename.lower() in shares:
        self.sessionsManager.current_session.set_share(sharename)
    else:
        self.logger.error("No share named '%s' on '%s'" % (sharename, self.sessionsManager.current_session.host))
