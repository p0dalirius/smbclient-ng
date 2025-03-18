#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : acls.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from smbclientng.utils import windows_ls_entry
from impacket.smb3structs import SMB2_0_INFO_SECURITY, SMB2_SEC_INFO_00, OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, READ_CONTROL, FILE_READ_ATTRIBUTES, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN
import ntpath


HELP = {
    "description": [
        "List ACLs of files and folders in cwd.", 
        "Syntax: 'acls'"
    ], 
    "subcommands": [],
    "autocomplete": ["remote_directory"]
}


@active_smb_connection_needed
@smb_share_is_set
def command_acls(self, arguments: list[str], command: str):
    # Command arguments required   : No
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    if len(arguments) == 0:
        arguments = ['.']
    
    smbClient = self.sessionsManager.current_session.smbClient
    sharename = self.sessionsManager.current_session.smb_share
    foldername = self.sessionsManager.current_session.smb_cwd
    tree_id = smbClient.connectTree(sharename)

    for entry in smbClient.listPath(sharename, ntpath.join(foldername, '*')):
        self.logger.print(windows_ls_entry(entry, self.config))
        filename = entry.get_longname()

        if filename in [".",".."]:
            continue
        filename = ntpath.join(foldername, filename)
        try:
            file_id = smbClient.getSMBServer().create(
                tree_id,
                filename,
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                0,
                FILE_DIRECTORY_FILE if entry.is_directory() else FILE_NON_DIRECTORY_FILE,
                FILE_OPEN,
                0
            )
        except Exception as err:
            self.logger.debug(f"Could not get attributes for file {filename}: {str(err)}")
            continue

        file_info = smbClient.getSMBServer().queryInfo(
            tree_id,
            file_id,
            infoType=SMB2_0_INFO_SECURITY,
            fileInfoClass=SMB2_SEC_INFO_00,
            additionalInformation=OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            flags=0
        )

        self.sessionsManager.current_session.printSecurityDescriptorTable(file_info, filename)

        self.logger.print()