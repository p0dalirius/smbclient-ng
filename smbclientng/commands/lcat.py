#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lcat.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command
from smbclientng.utils.decorator import command_arguments_required
from smbclientng.utils.utils import resolve_local_files
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
import os
import charset_normalizer


class Command_lcat(Command):
    name = "lcat"   
    description = "Print the contents of a local file."

    HELP = {
        "description": [
            description, 
            "Syntax: 'lcat <file>'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_file"]
    }
    
    @command_arguments_required
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        # Parse wildcards
        files_and_directories = resolve_local_files(arguments)

        for path_to_file in files_and_directories:
            # Read the file 
            try:
                if os.path.exists(path=path_to_file):
                    f = open(path_to_file, 'rb')
                    rawcontents = f.read()
                    #
                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]
                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            if len(files_and_directories) > 1:
                                interactive_shell.logger.print("\x1b[1;93m[>] %s\x1b[0m" % (path_to_file+' ').ljust(80,'='))
                            interactive_shell.logger.print(filecontent)
                        else:
                            interactive_shell.logger.error("[!] Could not detect charset of '%s'." % path_to_file)
                else:
                    interactive_shell.logger.error("[!] Local file '%s' does not exist." % path_to_file)
            except (SMBConnectionSessionError, SMB3SessionError) as e:
                interactive_shell.logger.error("[!] SMB Error: %s" % e)
