#!/usr/bin/env python3  
# -*- coding: utf-8 -*-
# File name          : lbat.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
from smbclientng.utils.utils import resolve_local_files
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
import os
import ntpath
import charset_normalizer
from rich.console import Console
from rich.syntax import Syntax


HELP = {
    "description": [
        "Pretty prints the contents of a local file.", 
        "Syntax: 'lbat <file>'"
    ], 
    "subcommands": [],
    "autocomplete": ["local_file"]
}


@command_arguments_required
def command_lbat(self, arguments: list[str], command: str):
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
                        lexer = Syntax.guess_lexer(path=ntpath.basename(path_to_file), code=filecontent)
                        # Some trickery for the files undetected by the lexer
                        if lexer == "default":
                            if '<?xml' in filecontent:
                                lexer = "xml"
                            elif '<html>' in filecontent:
                                lexer = "html"
                        syntax = Syntax(code=filecontent, line_numbers=True, lexer=lexer)
                        if len(files_and_directories) > 1:
                            self.logger.print("\x1b[1;93m[>] %s\x1b[0m" % (path_to_file+' ').ljust(80,'='))
                        Console().print(syntax)
                    else:
                        self.logger.error("[!] Could not detect charset of '%s'." % path_to_file)
            else:
                self.logger.error("[!] Local file '%s' does not exist." % path_to_file)
        except (SMBConnectionSessionError, SMB3SessionError) as e:
            self.logger.error("[!] SMB Error: %s" % e)
