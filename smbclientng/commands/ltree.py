#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ltree.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils import local_tree
from smbclientng.core.Command import Command


class Command_ltree(Command):
    HELP = {
        "description": [
            "Displays a tree view of the local directories.",
            "Syntax: 'ltree [directory]'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_directory"]
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) == 0:
            path = '.'
        else:
            path = arguments[0]

        if len(arguments) == 0:
            local_tree(path='.', config=interactive_shell.config)
        else:
            local_tree(path=path, config=interactive_shell.config)
