#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lrm.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
import os


HELP = {
    "description": [
        "Removes a local file.", 
        "Syntax: 'lrm <file>'"
    ], 
    "subcommands": [],
    "autocomplete": ["local_file"]
}


@command_arguments_required
def command_lrm(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : No
    # SMB share needed             : No

    path = arguments[0]

    if os.path.exists(path):
        if not os.path.isdir(s=path):
            try:
                os.remove(path=path)
            except Exception as e:
                self.logger.error("Error removing file '%s' : %s" % path)
        else:
            self.logger.error("Cannot delete '%s'. It is a directory, use 'lrmdir <directory>' instead." % path)
    else:
        self.logger.error("Path '%s' does not exist." % path)