#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : bat.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from smbclientng.utils.utils import resolve_remote_files
from rich.syntax import Syntax
from rich.console import Console
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
import charset_normalizer
import ntpath

HELP = {
    "description": [
        "Pretty prints the contents of a remote file.", 
        "Syntax: 'bat <file>'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_file"]
}

@command_arguments_required
@active_smb_connection_needed
@smb_share_is_set
def command_bat(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    # Parse wildcards
    files_and_directories = resolve_remote_files(self.sessionsManager.current_session, arguments)

    for path_to_file in files_and_directories:
        if self.sessionsManager.current_session.path_isfile(pathFromRoot=path_to_file):
            # Read the file
            try:    
                rawcontents = self.sessionsManager.current_session.read_file(path=path_to_file)
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
            except (SMBConnectionSessionError, SMB3SessionError) as e:
                self.logger.error("[!] SMB Error: %s" % e)