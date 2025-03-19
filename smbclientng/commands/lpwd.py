#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lpwd.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os


HELP = {
    "description": [
        "Shows the current local directory.", 
        "Syntax: 'lpwd'"
    ],
    "subcommands": [],
    "autocomplete": []
}


def command_lpwd(self, arguments: list[str], command: str):
    # Command arguments required   : No
    # Active SMB connection needed : No
    # SMB share needed             : No

    self.logger.print(os.getcwd())