#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : history.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import readline

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_history(Command):
    name = "history"
    description = "Displays the command history."

    HELP = {
        "description": [description, "Syntax: 'history'"],
        "subcommands": [],
        "autocomplete": [],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument(
            "--start",
            type=int,
            nargs="?",
            default=1,
            help="Start line of the history to display",
        )
        parser.add_argument(
            "--stop",
            type=int,
            nargs="?",
            default=None,
            help="Stop line of the history to display",
        )
        parser.add_argument(
            "--contains",
            type=str,
            help="Filter history by commands containing this string",
        )
        parser.add_argument(
            "--clear",
            default=False,
            action="store_true",
            help="Clear the command history",
        )
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        if self.options.clear:
            readline.clear_history()
            print("Command history cleared.")
            return

        else:
            # Start line
            if self.options.start is None:
                self.options.start = 1
            if self.options.start < 1:
                self.options.start = 1
            if self.options.start > readline.get_current_history_length():
                self.options.start = readline.get_current_history_length()

            # Stop line
            if self.options.stop is None:
                self.options.stop = readline.get_current_history_length()
            if self.options.stop < 1:
                self.options.stop = 1
            if self.options.stop > readline.get_current_history_length():
                self.options.stop = readline.get_current_history_length()

            format_string = "%%%dd | %%s" % len(str(self.options.stop))

            # Apply filters
            history = []
            for i in range(self.options.start, self.options.stop + 1):
                line = readline.get_history_item(i)
                if (
                    self.options.contains is not None
                    and self.options.contains not in line
                ):
                    continue
                history.append(format_string % (i, line))

            # Print history
            for line in history:
                print(line)
