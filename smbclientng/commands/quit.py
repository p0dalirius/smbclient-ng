#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : quit.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.commands.exit import Command_exit


class Command_quit(Command_exit):
    name = "quit"
    description = "Exits the interactive shell."

    HELP = {
        "description": [
            description,
            "Syntax: 'quit'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }