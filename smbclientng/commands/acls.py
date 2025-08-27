#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : acls.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import ntpath

from impacket.smb3structs import (DACL_SECURITY_INFORMATION,
                                  FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
                                  FILE_OPEN, FILE_READ_ATTRIBUTES,
                                  GROUP_SECURITY_INFORMATION,
                                  OWNER_SECURITY_INFORMATION, READ_CONTROL,
                                  SMB2_0_INFO_SECURITY, SMB2_SEC_INFO_00)

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils import windows_ls_entry
from smbclientng.utils.decorator import (active_smb_connection_needed,
                                         smb_share_is_set)
from smbclientng.utils.utils import resolve_remote_files


class Command_acls(Command):
    name = "acls"
    description = "List ACLs of files and folders in cwd."

    HELP = {
        "description": [description, "Syntax: 'acls'"],
        "subcommands": [],
        "autocomplete": ["remote_directory"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument(
            "files", nargs="*", help="Files or directories to retrieve ACLs for"
        )
        return parser

    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
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

        session = interactive_shell.sessionsManager.current_session
        tree_id = session.smbClient.connectTree(session.smb_share)

        for remotepath in files_and_directories:
            entry = session.get_entry(remotepath)

            interactive_shell.logger.print(
                windows_ls_entry(entry, interactive_shell.config)
            )
            filename = entry.get_longname()

            if filename in [".", ".."]:
                continue
            filename = ntpath.join(session.smb_cwd, filename)
            try:
                file_id = session.smbClient.getSMBServer().create(
                    tree_id,
                    filename,
                    READ_CONTROL | FILE_READ_ATTRIBUTES,
                    0,
                    (
                        FILE_DIRECTORY_FILE
                        if entry.is_directory()
                        else FILE_NON_DIRECTORY_FILE
                    ),
                    FILE_OPEN,
                    0,
                )
            except Exception as err:
                interactive_shell.logger.error(
                    f"Could not get attributes for file {filename}: {str(err)}"
                )
                continue

            try:
                file_info = session.smbClient.getSMBServer().queryInfo(
                    tree_id,
                    file_id,
                    infoType=SMB2_0_INFO_SECURITY,
                    fileInfoClass=SMB2_SEC_INFO_00,
                    additionalInformation=OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION,
                    flags=0,
                )
            except Exception as err:
                interactive_shell.logger.error(
                    f"Could not get attributes for file {filename}: {str(err)}"
                )
                continue

            session.printSecurityDescriptorTable(file_info, filename)

            interactive_shell.logger.print()
