#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : history.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import readline
from smbclientng.core.Command import Command


class Command_history(Command):
    HELP = {
        "description": [
            "Displays the command history.",
            "Syntax: 'history'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        history_length = readline.get_current_history_length()
        format_string = "%%%dd | %%s" % len(str(history_length))
        for i in range(1, history_length + 1):
            print(format_string % (i, readline.get_history_item(i)))
