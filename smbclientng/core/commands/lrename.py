#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lrename.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
import os


HELP = {
    "description": [
        "Renames a local file.", 
        "Syntax: 'lrename <oldfilename> <newfilename>'"
    ], 
    "subcommands": [],
    "autocomplete": ["local_file"]
}


@command_arguments_required
def command_lrename(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : No
    # SMB share needed             : No

    if len(arguments) == 2:
        os.rename(src=arguments[0], dst=arguments[1])
    else:
        self.commandCompleterObject.print_help(command=command)