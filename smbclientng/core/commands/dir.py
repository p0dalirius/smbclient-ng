#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : dir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.core.commands.ls import command_ls

    
HELP = {
    "description": [
        "List the contents of the current working directory.",
        "Syntax: 'dir'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_directory"]
}


def command_dir(self, arguments: list[str], command: str):
    command_ls(self, arguments, command)