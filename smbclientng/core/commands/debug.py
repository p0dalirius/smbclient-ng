#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : debug.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import traceback


HELP = {
    "description": [
        "Command for dev debugging.",
        "Syntax: 'debug'"
    ], 
    "subcommands": [],
    "autocomplete": []
}


def command_debug(self, arguments: list[str], command: str):
    try:
        self.logger.print("[debug] command    = '%s'" % command)
        self.logger.print("[debug] arguments  = %s" % arguments)
    except Exception as e:
        traceback.print_exc()