#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : find.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from smbclientng.core.Command import Command


class Command_find(Command):    
    HELP = {
        "description": [
            "Search for files in a directory hierarchy",
            "Syntax: find [-h] [-name NAME] [-iname INAME] [-type TYPE] [-size SIZE] [-ls]",
            "             [-download] [-maxdepth MAXDEPTH] [-mindepth MINDEPTH]",
            "             [--exclude-dir DIRNAME[:DEPTH[:CASE]]] [PATH ...]"
        ],
        "subcommands": [],
        "autocomplete": []
    }

    @classmethod
    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        module_name = "find"

        if module_name in interactive_shell.modules.keys():
            module = interactive_shell.modules[module_name](interactive_shell.sessionsManager.current_session, interactive_shell.config, interactive_shell.logger)
            arguments_string = ' '.join(arguments)
            module.run(arguments_string)
        else:
            interactive_shell.logger.error("Module '%s' does not exist." % module_name)