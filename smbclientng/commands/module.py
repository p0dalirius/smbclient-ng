#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : module.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
from smbclientng.types.Command import Command


class Command_module(Command):
    name = "module" 
    description = "Loads a specific module for additional functionalities."

    HELP = {
        "description": [
            description,
            "Syntax: 'module <name>'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }
    
    @command_arguments_required
    def run(self, interactive_shell, arguments: list[str], command: str):
        module_name = arguments[0]

        if module_name in interactive_shell.modules.keys():
            module = interactive_shell.modules[module_name](interactive_shell.sessionsManager.current_session, interactive_shell.config, interactive_shell.logger)
            arguments_string = ' '.join(arguments[1:])
            module.run(arguments_string)
        else:
            interactive_shell.logger.error("Module '%s' does not exist." % module_name)