#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : help.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.core.Command import Command


class Command_help(Command):
    HELP = {
        "description": [
            "Displays this help message.",
            "Syntax: 'help'"
        ], 
        "subcommands": ["format"],
        "autocomplete": []
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) != 0:
            interactive_shell.commandCompleterObject.print_help(command=arguments[0])
        else:
            interactive_shell.commandCompleterObject.print_help(command=None)