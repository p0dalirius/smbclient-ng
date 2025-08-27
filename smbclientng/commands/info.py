#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : info.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError as SMBConnectionSessionError

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.decorator import (active_smb_connection_needed,
                                         smb_share_is_set)


class Command_info(Command):
    name = "info"
    description = "Get information about the server and or the share."

    HELP = {
        "description": [description, "Syntax: 'info [server|share]'"],
        "subcommands": ["server", "share"],
        "autocomplete": [],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "--server",
            dest="print_server_info",
            action="store_true",
            help="Display server information",
        )
        group.add_argument(
            "--share",
            dest="print_share_info",
            action="store_true",
            help="Display share information",
        )
        return parser

    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        try:
            interactive_shell.sessionsManager.current_session.info(
                share=self.options.print_share_info,
                server=self.options.print_server_info,
            )
        except (SMBConnectionSessionError, SMB3SessionError) as e:
            interactive_shell.logger.error("SMB Error: %s" % e)
