#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : rm.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import ntpath    


HELP = {
    "description": [
        "Removes a remote file.", 
        "Syntax: 'rm <file>'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_file"]
}


def command_rm(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    for path_to_file in arguments:
        # Check if the path is absolute
        # Fullpath is required to check if path is a file
        if ntpath.isabs(path_to_file):
            full_path = ntpath.normpath(path_to_file)
        else:
            # Relative path, construct full path
            full_path = ntpath.normpath(ntpath.join(self.sessionsManager.current_session.smb_cwd, path_to_file))
        # Wildcard handling
        if '*' in path_to_file:
            self.sessionsManager.current_session.rm(path=path_to_file)
        # File
        elif self.sessionsManager.current_session.path_exists(path_to_file):
            if self.sessionsManager.current_session.path_isfile(full_path):
                try:
                    self.sessionsManager.current_session.rm(path=path_to_file)
                except Exception as e:
                    self.logger.error("Error removing file '%s' : %s" % path_to_file)
            else:
                self.logger.error("Cannot delete '%s': This is a directory, use 'rmdir <directory>' instead." % path_to_file)
        # File does not exist
        else:
            self.logger.error("Remote file '%s' does not exist." % path_to_file)