#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : rmdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from smbclientng.core.Command import Command


class Command_rmdir(Command):
    HELP = {
        "description": [
            "Removes a remote directory.", 
            "Syntax: 'rmdir <directory>'"
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

        for path_to_directory in arguments:
            if interactive_shell.sessionsManager.current_session.path_exists(path_to_directory):
                if interactive_shell.sessionsManager.current_session.path_isdir(path_to_directory):
                    try:
                        interactive_shell.sessionsManager.current_session.rmdir(path=path_to_directory)
                    except Exception as e:
                        interactive_shell.logger.error("Error removing directory '%s' : %s" % path_to_directory)
                else:
                    interactive_shell.logger.error("Cannot delete '%s': This is a file, use 'rm <file>' instead." % path_to_directory)
            else:
                interactive_shell.logger.error("Remote directory '%s' does not exist." % path_to_directory)
