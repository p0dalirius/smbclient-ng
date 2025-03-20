#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ls.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from smbclientng.utils.utils import resolve_remote_files, windows_ls_entry
from smbclientng.types.Command import Command


class Command_ls(Command):
    name = "ls"
    description = "List the contents of the current remote working directory."

    HELP = {
        "description": [
            description, 
            "Syntax: 'ls'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        if len(arguments) == 0:
            arguments = ['.']
        else:
            arguments = resolve_remote_files(interactive_shell.sessionsManager.current_session, arguments)

        for path in arguments:
            if len(arguments) > 1:
                interactive_shell.logger.print("%s:" % path)

            if interactive_shell.sessionsManager.current_session.path_isdir(pathFromRoot=path):
                # Read the files
                directory_contents = interactive_shell.sessionsManager.current_session.list_contents(path=path)
            else:
                entry = interactive_shell.sessionsManager.current_session.get_entry(path=path)
                if entry is not None:
                    directory_contents = {entry.get_longname(): entry}
                else:
                    directory_contents = {}

            for longname in sorted(directory_contents.keys(), key=lambda x:x.lower()):
                interactive_shell.logger.print(windows_ls_entry(directory_contents[longname], interactive_shell.config))

            if len(arguments) > 1:
                interactive_shell.logger.print()