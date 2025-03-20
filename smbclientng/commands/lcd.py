#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lcd.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
import os
from smbclientng.core.Command import Command


class Command_lcd(Command):
    HELP = {
        "description": [
            "Changes the current local directory.",
            "Syntax: 'lcd <directory>'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_directory"]
    }

    @classmethod
    @command_arguments_required
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No
        
        path = arguments[0]

        if os.path.exists(path=path):
            if os.path.isdir(s=path):
                os.chdir(path=path)
            else:
                interactive_shell.logger.error("Path '%s' is not a directory." % path)
        else:
            interactive_shell.logger.error("Directory '%s' does not exists." % path)