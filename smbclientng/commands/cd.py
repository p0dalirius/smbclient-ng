#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : cd.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import argparse 
from smbclientng.utils.decorator import command_arguments_required, active_smb_connection_needed, smb_share_is_set
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser


class Command_cd(Command):
    name = "cd"
    description = "Change the current working directory."

    HELP = {
        "description": [
            description, 
            "Syntax: 'cd <directory>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_directory"]
    }
    
    def setupParser(self) -> argparse.ArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)

        parser.add_argument('directory', help='Directory to change to')

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

        try:
            interactive_shell.sessionsManager.current_session.set_cwd(path=self.options.directory)
        except (SMBConnectionSessionError, SMB3SessionError) as e:
            interactive_shell.logger.error("[!] SMB Error: %s" % e)