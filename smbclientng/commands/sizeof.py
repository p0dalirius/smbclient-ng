#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : sizeof.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import ntpath

from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError as SMBConnectionSessionError

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils import b_filesize, smb_entry_iterator
from smbclientng.utils.decorator import (active_smb_connection_needed,
                                         smb_share_is_set)


class Command_sizeof(Command):
    name = "sizeof"
    description = "Recursively compute the size of a folder."

    HELP = {
        "description": [description, "Syntax: 'sizeof [directory|file]'"],
        "subcommands": [],
        "autocomplete": ["remote_directory"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument(
            "path",
            type=str,
            nargs="*",
            help="List of remote directories or files to compute the size of",
        )
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

        # Parse the arguments to get the path(s)
        if len(self.options.path) == 0:
            self.options.path = ["."]

        total_size = 0
        for path in self.options.path:
            # Normalize and parse the path
            path = path.replace("/", ntpath.sep)
            path = ntpath.normpath(path)
            path = path.strip(ntpath.sep)

            # Handle relative and absolute paths
            if not ntpath.isabs(path):
                path = ntpath.normpath(
                    ntpath.join(
                        interactive_shell.sessionsManager.current_session.smb_cwd or "",
                        path,
                    )
                )
            else:
                path = path.lstrip(ntpath.sep)
                path = ntpath.normpath(path)

            try:
                # Initialize the generator
                generator = smb_entry_iterator(
                    smb_client=interactive_shell.sessionsManager.current_session.smbClient,
                    smb_share=interactive_shell.sessionsManager.current_session.smb_share,
                    start_paths=[path],
                    exclusion_rules=[],
                    max_depth=None,
                )

                path_size = 0

                LINE_CLEAR = "\x1b[2K"

                # Prepare the path display
                if interactive_shell.config.no_colors:
                    path_display = path
                else:
                    path_display = f"\x1b[1;96m{path}\x1b[0m"

                size_str = ""
                for entry, fullpath, depth, is_last_entry in generator:
                    if not entry.is_directory():
                        path_size += entry.get_filesize()
                        # Update the size display each time path_size is incremented
                        size_str = b_filesize(path_size)
                        output_line = f"\r{size_str}\t{path_display}"
                        # Clear the line after the cursor
                        print(output_line, end="\r")

                # After processing all entries, format and print the result for the current path
                print(end=LINE_CLEAR)
                print(f"{size_str}\t{path_display}")
                total_size += path_size

            except (SMBConnectionSessionError, SMB3SessionError) as e:
                interactive_shell.logger.error(f"Failed to access '{path}': {e}")
            except (BrokenPipeError, KeyboardInterrupt):
                interactive_shell.logger.error("Interrupted.")
                return
            except Exception as e:
                interactive_shell.logger.error(f"Error while processing '{path}': {e}")

        # If multiple paths, print the total size
        if len(self.options.path) > 1:
            interactive_shell.logger.print("──────────────────────")
            interactive_shell.logger.print(f"Total size: {b_filesize(total_size)}")
