#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : bat.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import ntpath

import charset_normalizer
from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from rich.console import Console
from rich.syntax import Syntax

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.decorator import (active_smb_connection_needed,
                                         smb_share_is_set)
from smbclientng.utils.utils import resolve_remote_files


class Command_bat(Command):
    name = "bat"
    description = "Pretty prints the contents of a remote file."

    HELP = {
        "description": [description, "Syntax: 'bat <file>'"],
        "subcommands": [],
        "autocomplete": ["remote_file"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument("files", nargs="*", help="Files or directories to get")
        return parser

    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        if len(self.options.files) == 0:
            self.options.files = ["*"]

        # Parse wildcards
        files_and_directories = resolve_remote_files(
            interactive_shell.sessionsManager.current_session, self.options.files
        )

        for path_to_file in files_and_directories:
            if interactive_shell.sessionsManager.current_session.path_isfile(
                pathFromRoot=path_to_file
            ):
                # Read the file
                try:
                    rawcontents = (
                        interactive_shell.sessionsManager.current_session.read_file(
                            path=path_to_file
                        )
                    )
                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]
                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            lexer = Syntax.guess_lexer(
                                path=ntpath.basename(path_to_file), code=filecontent
                            )
                            # Some trickery for the files undetected by the lexer
                            if lexer == "default":
                                if "<?xml" in filecontent:
                                    lexer = "xml"
                                elif "<html>" in filecontent:
                                    lexer = "html"
                            syntax = Syntax(
                                code=filecontent, line_numbers=True, lexer=lexer
                            )
                            if len(files_and_directories) > 1:
                                interactive_shell.logger.print(
                                    "\x1b[1;93m[>] %s\x1b[0m"
                                    % (path_to_file + " ").ljust(80, "=")
                                )
                            Console().print(syntax)
                        else:
                            interactive_shell.logger.error(
                                "[!] Could not detect charset of '%s'." % path_to_file
                            )
                except (SMBConnectionSessionError, SMB3SessionError) as e:
                    interactive_shell.logger.error("[!] SMB Error: %s" % e)
