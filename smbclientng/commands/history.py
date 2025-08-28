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
        parser.add_argument(
            "-t",
            "--timestamps",
            default=False,
            action="store_true",
            help="Show timestamps for each command in history",
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
            if hasattr(interactive_shell, "history") and isinstance(
                interactive_shell.history, list
            ):
                interactive_shell.history.clear()
            print("Command history cleared.")
            return

        else:
            # Choose history source
            history_with_ts = getattr(interactive_shell, "history", None)
            use_ts_source = (
                isinstance(history_with_ts, list) and len(history_with_ts) > 0
            )

            # Determine history length
            if use_ts_source:
                hist_len = len(history_with_ts)
            else:
                hist_len = readline.get_current_history_length()

            # Start line
            if self.options.start is None:
                self.options.start = 1
            if self.options.start < 1:
                self.options.start = 1
            if self.options.start > hist_len:
                self.options.start = hist_len

            # Stop line
            if self.options.stop is None:
                self.options.stop = hist_len
            if self.options.stop < 1:
                self.options.stop = 1
            if self.options.stop > hist_len:
                self.options.stop = hist_len

            width = len(str(self.options.stop))
            if self.options.timestamps and use_ts_source:
                format_string = "%%%dd | %%s | %%s" % width
            else:
                format_string = "%%%dd | %%s" % width

            # Apply filters
            history = []
            for i in range(self.options.start, self.options.stop + 1):
                if self.options.timestamps and use_ts_source:
                    # Use in-memory timestamped history
                    try:
                        ts, line = history_with_ts[i - 1]
                    except Exception:
                        continue
                    if self.options.contains is not None and (
                        line is None or self.options.contains not in line
                    ):
                        continue
                    timestamp_str = ts.strftime("%Y-%m-%d %H:%M:%S")
                    history.append(format_string % (i, timestamp_str, line))
                else:
                    # Fallback to readline only
                    line = readline.get_history_item(i)
                    if self.options.contains is not None and (
                        line is None or self.options.contains not in line
                    ):
                        continue
                    if line is None:
                        continue
                    history.append(format_string % (i, line))

            # Print history
            for line in history:
                print(line)
