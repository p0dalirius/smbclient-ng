#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : module.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


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

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('module', type=str, nargs='?', help='Module name')
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return 

        if self.options.module in interactive_shell.modules.keys():
            module = interactive_shell.modules[self.options.module](interactive_shell.sessionsManager.current_session, interactive_shell.config, interactive_shell.logger)
            arguments_string = ' '.join(arguments[1:])
            module.run(arguments_string)
        else:
            interactive_shell.logger.error("Module '%s' does not exist." % self.options.module)