#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : umount.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set


HELP = {
    "description": [
        "Removes a mount point of the remote share on the local machine.",
        "Syntax: 'umount <local_mount_point>'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_directory"]
}


@command_arguments_required
@active_smb_connection_needed
@smb_share_is_set
def command_umount(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    local_mount_point = arguments[0]

    self.logger.debug("Trying to unmount local mount point '%s'" % (local_mount_point))
    
    self.sessionsManager.current_session.umount(local_mount_point)