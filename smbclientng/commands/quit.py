#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : quit.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.core.Command import Command


class Command_quit(Command):
    HELP = {
        "description": [
            "Exits the interactive shell.",
            "Syntax: 'quit'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        interactive_shell.running = False