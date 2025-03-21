#!/usr/bin/env python3  
# -*- coding: utf-8 -*-
# File name          : lbat.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.utils import resolve_local_files
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
from rich.console import Console
from rich.syntax import Syntax
import charset_normalizer
import os
import ntpath


class Command_lbat(Command):
    name = "lbat"
    description = "Pretty prints the contents of a local file."

    HELP = {
        "description": [
            description, 
            "Syntax: 'lbat <file>'"
        ], 
        "subcommands": [],
        "autocomplete": ["local_file"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('files', nargs='*', help='Local files to pretty print')
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return 
        
        if len(self.options.files) == 0:
            self.options.files = ['*']


        # Parse wildcards
        local_files = resolve_local_files(self.options.files)

        for path_to_file in local_files:
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
                            lexer = Syntax.guess_lexer(path=ntpath.basename(path_to_file), code=filecontent)
                            # Some trickery for the files undetected by the lexer
                            if lexer == "default":
                                if '<?xml' in filecontent:
                                    lexer = "xml"
                                elif '<html>' in filecontent:
                                    lexer = "html"
                            syntax = Syntax(code=filecontent, line_numbers=True, lexer=lexer)
                            if len(local_files) > 1:
                                interactive_shell.logger.print("\x1b[1;93m[>] %s\x1b[0m" % (path_to_file+' ').ljust(80,'='))
                            Console().print(syntax)
                        else:
                            interactive_shell.logger.error("[!] Could not detect charset of '%s'." % path_to_file)
                else:
                    interactive_shell.logger.error("[!] Local file '%s' does not exist." % path_to_file)
            except (SMBConnectionSessionError, SMB3SessionError) as e:
                interactive_shell.logger.error("[!] SMB Error: %s" % e)
