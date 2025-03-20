#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : sessions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command


class Command_sessions(Command):
    name = "sessions"
    description = "Manage the SMB sessions."

    HELP = {
        "description": [
            description, 
            "Syntax: 'sessions [access|create|delete|execute|list]'"
        ], 
        "subcommands": ["create", "delete", "execute", "interact", "list"],
        "autocomplete": []
    }
  
    def run(self, interactive_shell, arguments: list[str], command: str):
        interactive_shell.sessionsManager.process_command_line(arguments)