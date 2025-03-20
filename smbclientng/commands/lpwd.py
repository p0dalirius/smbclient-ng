#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lpwd.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os
from smbclientng.types.Command import Command


class Command_lpwd(Command):
    name = "lpwd"
    description = "Shows the current local directory."

    HELP = {
        "description": [
            description,
            "Syntax: 'lpwd'"
        ],
        "subcommands": [],
        "autocomplete": []
    }
    
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        interactive_shell.logger.print(os.getcwd())