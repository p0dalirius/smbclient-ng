#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lpwd.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os
from smbclientng.core.Command import Command

class Command_lpwd(Command):
    HELP = {
        "description": [
            "Shows the current local directory.", 
            "Syntax: 'lpwd'"
        ],
        "subcommands": [],
        "autocomplete": []
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        interactive_shell.logger.print(os.getcwd())