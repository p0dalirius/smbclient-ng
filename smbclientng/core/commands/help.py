#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : help.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025


HELP = {
    "description": [
        "Displays this help message.",
        "Syntax: 'help'"
    ], 
    "subcommands": ["format"],
    "autocomplete": []
}


def command_help(self, arguments: list[str], command: str):
    # Command arguments required   : No
    # Active SMB connection needed : No
    # SMB share needed             : No

    if len(arguments) != 0:
        self.commandCompleterObject.print_help(command=arguments[0])
    else:
        self.commandCompleterObject.print_help(command=None)