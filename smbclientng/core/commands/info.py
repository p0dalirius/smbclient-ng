#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : info.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError


HELP = {
    "description": [
        "Get information about the server and or the share.",
        "Syntax: 'info [server|share]'"
    ], 
    "subcommands": ["server", "share"],
    "autocomplete": []
}


@command_arguments_required
@active_smb_connection_needed
@smb_share_is_set
def command_info(self, arguments: list[str], command: str):
    # Command arguments required   : No
    # Active SMB connection needed : Yes
    # SMB share needed             : No

    print_server_info = False
    print_share_info = False
    if len(arguments) != 0:
        if arguments[0].lower() not in ["server", "share"]:
            self.logger.error("'%s' is not a valid parameter. Use 'server' or 'share'." % arguments[0])
            return None
        print_server_info = (arguments[0].lower() == "server")
        print_share_info = (arguments[0].lower() == "share")
    else:
        print_server_info = True
        print_share_info = True

    try:
        self.sessionsManager.current_session.info(
            share=print_share_info,
            server=print_server_info
        )
    except (SMBConnectionSessionError, SMB3SessionError) as e:
        self.logger.error("SMB Error: %s" % e)