#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lcp.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
import os
import shutil


class Command_lcp(Command):
    name = "lcp"
    description = "Create a copy of a local file."

    HELP = {
        "description": [
            description,
            "Syntax: 'lcp <srcfile> <dstfile>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_file"]
    }
    
    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument('srcfile', type=str, help='The source file')
        parser.add_argument('dstfile', type=str, help='The destination file')
        return parser

    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return 

        if os.path.exists(path=self.options.srcfile):
            try:
                shutil.copyfile(src=self.options.srcfile, dst=self.options.dstfile)
            except shutil.SameFileError as err:
                interactive_shell.logger.error("[!] Error: %s" % err)
        else:
            interactive_shell.logger.error("[!] File '%s' does not exists." % self.options.srcfile)