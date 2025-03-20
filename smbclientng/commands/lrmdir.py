#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lrmdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
import os
import shutil
from smbclientng.types.Command import Command
    

class Command_lrmdir(Command):
    name = "lrmdir"
    description = "Removes a local directory."

    HELP = {
        "description": [
            description, 
            "Syntax: 'lrmdir <directory>'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_directory"]
    }
    
    @command_arguments_required
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) == 0:
            path = '.'
        else:
            path = arguments[0]

        if os.path.exists(path):
            if os.path.isdir(s=path):
                try:
                    shutil.rmtree(path=path)
                except Exception as e:
                    interactive_shell.logger.error("Error removing directory '%s' : %s" % path)
            else:
                interactive_shell.logger.error("Cannot delete '%s'. It is a file, use 'lrm <file>' instead." % path)
        else:
            interactive_shell.logger.error("Path '%s' does not exist." % path)