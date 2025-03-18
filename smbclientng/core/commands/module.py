#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : module.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required


HELP = {
    "description": [
        "Loads a specific module for additional functionalities.",
        "Syntax: 'module <name>'"
    ], 
    "subcommands": [],
    "autocomplete": []
}


@command_arguments_required
def command_module(self, arguments: list[str], command: str):
    module_name = arguments[0]

    if module_name in self.modules.keys():
        module = self.modules[module_name](self.sessionsManager.current_session, self.config, self.logger)
        arguments_string = ' '.join(arguments[1:])
        module.run(arguments_string)
    else:
        self.logger.error("Module '%s' does not exist." % module_name)