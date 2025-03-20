#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : umount.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
import os


class Command_umount(Command):
    name = "umount"
    description = "Removes a mount point of the remote share on the local machine."

    HELP = {
        "description": [
            description,
            "Syntax: 'umount <local_mount_point>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('local_mount_point', type=str, help='Local mount point to unmount')
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

        if not os.path.exists(self.options.local_mount_point):
            interactive_shell.logger.error("Local mount point '%s' does not exist" % (self.options.local_mount_point))
            return

        interactive_shell.logger.debug("Trying to unmount local mount point '%s'" % (self.options.local_mount_point))
        
        interactive_shell.sessionsManager.current_session.umount(self.options.local_mount_point)