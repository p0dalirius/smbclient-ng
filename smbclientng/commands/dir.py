#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : dir.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.commands.ls import Command_ls
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
    

class Command_dir(Command_ls):
    name = "dir"
    description = "List the contents of the current working directory."

    HELP = {
        "description": [
            description,
            "Syntax: 'dir'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        return super().setupParser()
