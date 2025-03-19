#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : rmdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set


HELP = {
    "description": [
        "Removes a remote directory.", 
        "Syntax: 'rmdir <directory>'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_directory"]
}


@command_arguments_required
@active_smb_connection_needed
@smb_share_is_set
def command_rmdir(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    for path_to_directory in arguments:
        if self.sessionsManager.current_session.path_exists(path_to_directory):
            if self.sessionsManager.current_session.path_isdir(path_to_directory):
                try:
                    self.sessionsManager.current_session.rmdir(path=path_to_directory)
                except Exception as e:
                    self.logger.error("Error removing directory '%s' : %s" % path_to_directory)
            else:
                self.logger.error("Cannot delete '%s': This is a file, use 'rm <file>' instead." % path_to_directory)
        else:
            self.logger.error("Remote directory '%s' does not exist." % path_to_directory)
