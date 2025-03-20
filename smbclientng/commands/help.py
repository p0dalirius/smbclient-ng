#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : help.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command
import argparse


class Command_help(Command):
    name = "help"
    description = "Displays this help message."

    HELP = {
        "description": [
            description,
        ], 
        "subcommands": ["format"],
        "autocomplete": []
    }

    def setupParser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument('command', nargs='?', help='The command to get help for')
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)

        if len(arguments) != 0:
            interactive_shell.commandCompleterObject.print_help(command=arguments[0])
        else:
            interactive_shell.commandCompleterObject.print_help(command=None)