#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lcat.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import os

import charset_normalizer
from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError as SMBConnectionSessionError

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.utils import resolve_local_files


class Command_lcat(Command):
    name = "lcat"
    description = "Print the contents of a local file."

    HELP = {
        "description": [description, "Syntax: 'lcat <file>'"],
        "subcommands": [],
        "autocomplete": ["local_file"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument("files", nargs="*", help="Local files to display")
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        if len(self.options.files) == 0:
            self.options.files = ["*"]

        # Parse wildcards
        local_files = resolve_local_files(self.options.files)

        for path_to_file in local_files:
            # Read the file
            try:
                if os.path.exists(path=path_to_file):
                    f = open(path_to_file, "rb")
                    rawcontents = f.read()
                    #
                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]
                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            if len(local_files) > 1:
                                interactive_shell.logger.print(
                                    "\x1b[1;93m[>] %s\x1b[0m"
                                    % (path_to_file + " ").ljust(80, "=")
                                )
                            interactive_shell.logger.print(filecontent)
                        else:
                            interactive_shell.logger.error(
                                "[!] Could not detect charset of '%s'." % path_to_file
                            )
                else:
                    interactive_shell.logger.error(
                        "[!] Local file '%s' does not exist." % path_to_file
                    )
            except (SMBConnectionSessionError, SMB3SessionError) as e:
                interactive_shell.logger.error("[!] SMB Error: %s" % e)
