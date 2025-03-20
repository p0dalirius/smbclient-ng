#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : mount.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
import ntpath
import os
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_mount(Command):
    name = "mount"
    description = "Creates a mount point of the remote share on the local machine."

    HELP = {
        "description": [
            description,
            "Syntax: 'mount <remote_path> <local_mountpoint>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('remote_path', type=str, help='Remote path to mount')
        parser.add_argument('local_mountpoint', type=str, help='Local mountpoint')
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

        if not self.options.remote_path.startswith(ntpath.sep):
            self.options.remote_path = interactive_shell.sessionsManager.current_session.smb_cwd + ntpath.sep + self.options.remote_path

        if not os.path.exists(self.options.local_mountpoint):
            interactive_shell.logger.debug("Local mountpoint '%s' does not exist, creating it." % self.options.local_mountpoint)
            os.makedirs(self.options.local_mountpoint)

        interactive_shell.logger.debug("Trying to mount remote '%s' onto local '%s'" % (self.options.remote_path, self.options.local_mountpoint))

        try:
            interactive_shell.sessionsManager.current_session.mount(local_mount_point=self.options.local_mountpoint, remote_path=self.options.remote_path)
        except (SMBConnectionSessionError, SMB3SessionError) as e:
            interactive_shell.sessionsManager.current_session.umount(local_mount_point=self.options.local_mountpoint)