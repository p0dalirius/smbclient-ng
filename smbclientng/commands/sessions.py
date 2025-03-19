#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : sessions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025


HELP = {
    "description": [
        "Manage the SMB sessions.", 
        "Syntax: 'sessions [access|create|delete|execute|list]'"
    ], 
    "subcommands": ["create", "delete", "execute", "interact", "list"],
    "autocomplete": []
}


def command_sessions(self, arguments: list[str], command: str):
    self.sessionsManager.process_command_line(arguments)