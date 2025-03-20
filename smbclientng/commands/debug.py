#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : debug.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import traceback
from smbclientng.core.Command import Command


class Command_debug(Command):
    HELP = {
        "description": [
            "Command for dev debugging.",
            "Syntax: 'debug'"
        ], 
        "subcommands": [],
        "autocomplete": []
    }

    @classmethod
    def run(cls, interactive_shell, arguments: list[str], command: str):
        try:
            interactive_shell.logger.print("[debug] command    = '%s'" % command)
            interactive_shell.logger.print("[debug] arguments  = %s" % arguments)
        except Exception as e:
            traceback.print_exc()