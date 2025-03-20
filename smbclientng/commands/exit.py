#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : exit.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.core.Command import Command


class Command_exit(Command):
    HELP = {
        "description": [
            "Exits the interactive shell.",
            "Syntax: 'exit'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        interactive_shell.running = False