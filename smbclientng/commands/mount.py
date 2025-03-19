#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : mount.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
import ntpath


HELP = {
    "description": [
        "Creates a mount point of the remote share on the local machine.",
        "Syntax: 'mount <remote_path> <local_mountpoint>'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_directory"]
}


@command_arguments_required
@active_smb_connection_needed
@smb_share_is_set
def command_mount(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    if len(arguments) == 2:
        remote_path = arguments[0]
        if not remote_path.startswith(ntpath.sep):
            remote_path = self.sessionsManager.current_session.smb_cwd + ntpath.sep + remote_path

        local_mount_point = arguments[1]

        self.logger.debug("Trying to mount remote '%s' onto local '%s'" % (remote_path, local_mount_point))

        try:
            self.sessionsManager.current_session.mount(local_mount_point, remote_path)
        except (SMBConnectionSessionError, SMB3SessionError) as e:
            self.sessionsManager.current_session.umount(local_mount_point)
    else:
        self.commandCompleterObject.print_help(command=command)