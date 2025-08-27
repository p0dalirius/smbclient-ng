#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lls.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import datetime
import os

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.utils import (b_filesize, resolve_local_files,
                                     unix_permissions)


class Command_lls(Command):
    name = "lls"
    description = "Lists the contents of the current local directory."

    HELP = {
        "description": [description, "Syntax: 'lls'"],
        "subcommands": [],
        "autocomplete": ["local_directory"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument("files", nargs="*", help="Local files to list")
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        if len(self.options.files) == 0:
            self.options.files = ["."]

        # Parse wildcards
        local_files = resolve_local_files(self.options.files)

        for path in local_files:
            if len(local_files) > 1:
                interactive_shell.logger.print("%s:" % path)
            # lls <directory>
            if os.path.isdir(path):
                directory_contents = os.listdir(path=path)
                for entryname in sorted(directory_contents):
                    path_to_file = path + os.path.sep + entryname
                    rights_str = unix_permissions(path_to_file)
                    size_str = b_filesize(os.path.getsize(filename=path_to_file))
                    date_str = datetime.datetime.fromtimestamp(
                        os.path.getmtime(filename=path_to_file)
                    ).strftime("%Y-%m-%d %H:%M")

                    if os.path.isdir(s=entryname):
                        if interactive_shell.config.no_colors:
                            interactive_shell.logger.print(
                                "%s %10s  %s  %s%s"
                                % (
                                    rights_str,
                                    size_str,
                                    date_str,
                                    entryname,
                                    os.path.sep,
                                )
                            )
                        else:
                            interactive_shell.logger.print(
                                "%s %10s  %s  \x1b[1;96m%s\x1b[0m%s"
                                % (
                                    rights_str,
                                    size_str,
                                    date_str,
                                    entryname,
                                    os.path.sep,
                                )
                            )
                    else:
                        if interactive_shell.config.no_colors:
                            interactive_shell.logger.print(
                                "%s %10s  %s  %s"
                                % (rights_str, size_str, date_str, entryname)
                            )
                        else:
                            interactive_shell.logger.print(
                                "%s %10s  %s  \x1b[1m%s\x1b[0m"
                                % (rights_str, size_str, date_str, entryname)
                            )
            # lls <file>
            elif os.path.isfile(path):
                rights_str = unix_permissions(path)
                size_str = b_filesize(os.path.getsize(filename=path))
                date_str = datetime.datetime.fromtimestamp(
                    os.path.getmtime(filename=path)
                ).strftime("%Y-%m-%d %H:%M")
                if interactive_shell.config.no_colors:
                    interactive_shell.logger.print(
                        "%s %10s  %s  %s"
                        % (rights_str, size_str, date_str, os.path.basename(path))
                    )
                else:
                    interactive_shell.logger.print(
                        "%s %10s  %s  \x1b[1m%s\x1b[0m"
                        % (rights_str, size_str, date_str, os.path.basename(path))
                    )

            if len(arguments) > 1:
                interactive_shell.logger.print()
