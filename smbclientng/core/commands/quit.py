#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : quit.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025


HELP = {
    "description": [
        "Exits the interactive shell.",
        "Syntax: 'quit'"
    ], 
    "subcommands": [],
    "autocomplete": []
}


def command_quit(self, arguments: list[str], command: str):
    self.running = False