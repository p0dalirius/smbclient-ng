#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : sessions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.core.Command import Command


class Command_sessions(Command):
    HELP = {
        "description": [
            "Manage the SMB sessions.", 
            "Syntax: 'sessions [access|create|delete|execute|list]'"
        ], 
        "subcommands": ["create", "delete", "execute", "interact", "list"],
        "autocomplete": []
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        interactive_shell.sessionsManager.process_command_line(arguments)