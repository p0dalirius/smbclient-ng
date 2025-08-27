#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : use.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import argparse

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.decorator import active_smb_connection_needed


class Command_use(Command):
    name = "use"
    description = "Use a SMB share."

    HELP = {
        "description": [
            description,
        ],
        "subcommands": [],
        "autocomplete": ["share"],
    }

    def setupParser(self) -> argparse.ArgumentParser:
        parser = CommandArgumentParser(description=self.description)
        parser.add_argument("sharename", help="The name of the share to use")
        return parser

    @active_smb_connection_needed
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)

        sharename = arguments[0]

        # Reload the list of shares
        shares = interactive_shell.sessionsManager.current_session.list_shares()
        shares = [s.lower() for s in shares.keys()]

        if sharename.lower() in shares:
            interactive_shell.sessionsManager.current_session.set_share(sharename)
        else:
            interactive_shell.logger.error(
                "No share named '%s' on '%s'"
                % (sharename, interactive_shell.sessionsManager.current_session.host)
            )
