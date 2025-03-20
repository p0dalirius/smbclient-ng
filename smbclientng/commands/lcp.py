#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : lcp.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import command_arguments_required
import os
import shutil
from smbclientng.core.Command import Command


class Command_lcp(Command):
    HELP = {
        "description": [
            "Create a copy of a local file.",
            "Syntax: 'lcp <srcfile> <dstfile>'"
        ], 
        "subcommands": [],
        "autocomplete": ["remote_file"]
    }

    @classmethod
    @command_arguments_required
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) == 2:
            src_path = arguments[0]
            dst_path = arguments[1]
            if os.path.exists(path=src_path):
                try:
                    shutil.copyfile(src=src_path, dst=dst_path)
                except shutil.SameFileError as err:
                    interactive_shell.logger.error("[!] Error: %s" % err)
            else:
                interactive_shell.logger.error("[!] File '%s' does not exists." % src_path)
        else:
            interactive_shell.commandCompleterObject.print_help(command=command)