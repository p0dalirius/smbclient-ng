#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : exit.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command


class Command_exit(Command):
    name = "exit"
    description = "Exits the interactive shell."

    HELP = {
        "description": [
            description,
            "Syntax: 'exit'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }
    
    def run(self, interactive_shell, arguments: list[str], command: str):
        interactive_shell.running = False