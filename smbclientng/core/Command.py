#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Command.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 mar 2025

from __future__ import annotations
import argparse
import shlex
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from smbclientng.core.SMBSession import SMBSession
    from smbclientng.core.Logger import Logger
    from smbclientng.core.Config import Config


class Command(object):
    """
    A parent class for all Commands in the smbclient-ng tool.

    This class provides common attributes and methods that are shared among different Commands.
    """

    name: str = ""
    description: str = ""
    smbSession: SMBSession
    options: argparse.Namespace

    def __init__(self, smbSession: SMBSession, config: Config, logger: Logger):
        self.smbSession = smbSession
        self.config = config
        self.logger = logger

    def parseArgs(self):
        raise NotImplementedError("Subclasses must implement this method")

    def run(self):
        """
        Placeholder method for running the Command.

        This method should be implemented by subclasses to define the specific behavior of the Command.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def processArguments(self, parser: argparse.ArgumentParser, arguments) -> argparse.Namespace:
        if type(arguments) == list:
            arguments = ' '.join(arguments)
        
        __iterableArguments = shlex.split(arguments)

        try:
            self.options = parser.parse_args(__iterableArguments)
        except SystemExit as e:
            pass

        return self.options
        
