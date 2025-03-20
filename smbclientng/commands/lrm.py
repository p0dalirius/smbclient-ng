#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lrm.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
import os
from smbclientng.types.Command import Command


class Command_lrm(Command):
    name = "lrm"
    description = "Removes a local file."

    HELP = {
        "description": [
            description, 
            "Syntax: 'lrm <file>'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_file"]
    }

    @command_arguments_required
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        path = arguments[0]

        if os.path.exists(path):
            if not os.path.isdir(s=path):
                try:
                    os.remove(path=path)
                except Exception as e:
                    interactive_shell.logger.error("Error removing file '%s' : %s" % path)
            else:
                interactive_shell.logger.error("Cannot delete '%s'. It is a directory, use 'lrmdir <directory>' instead." % path)
        else:
            interactive_shell.logger.error("Path '%s' does not exist." % path)