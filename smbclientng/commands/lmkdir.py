#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lmkdir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
import os
from smbclientng.core.Command import Command


class Command_lmkdir(Command):
    HELP = {
        "description": [
            "Creates a new local directory.", 
            "Syntax: 'lmkdir <directory>'"
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

        for path in arguments:
            if os.path.sep in path:
                path = path.strip(os.path.sep).split(os.path.sep)
            else:
                path = [path]

            # Create each dir in the path
            for depth in range(1, len(path)+1):
                tmp_path = os.path.sep.join(path[:depth])
                if not os.path.exists(tmp_path):
                    os.mkdir(path=tmp_path)