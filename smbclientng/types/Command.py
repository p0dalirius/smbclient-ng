#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Command.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 mar 2025

from __future__ import annotations
import argparse
import shlex
from smbclientng.types.CommandArgumentParser import CommandArgumentParserError
from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from smbclientng.core.SMBSession import SMBSession
    from smbclientng.core.Logger import Logger
    from smbclientng.types.Config import Config


class Command(object):
    """
    A parent class for all Commands in the smbclient-ng tool.

    This class provides common attributes and methods that are shared among different Commands.
    """

    name: str = ""
    description: str = ""

    smbSession: Optional[SMBSession] = None
    config: Optional[Config] = None
    logger: Optional[Logger] = None

    options: Optional[argparse.Namespace] = None
    parser: Optional[argparse.ArgumentParser] = None

    def __init__(self, smbSession: Optional[SMBSession] = None, config: Optional[Config] = None, logger: Optional[Logger] = None):
        self.smbSession = smbSession
        self.config = config
        self.logger = logger

        self.parser = self.setupParser()

        if self.parser is not None:
            kept_lines = []
            for line in self.HELP["description"]:
                if not line.strip().lower().startswith("syntax:"):
                    kept_lines.append(line)
            usage = ':'.join(self.parser.format_usage().strip().split(":")[1:])
            kept_lines.append("Syntax: '%s'" % (usage))
            self.HELP["description"] = kept_lines

    def setupParser(self) -> argparse.ArgumentParser:
        raise NotImplementedError("Subclasses must implement this method")

    def run(self):
        """
        Placeholder method for running the Command.

        This method should be implemented by subclasses to define the specific behavior of the Command.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def processArguments(self, arguments) -> argparse.Namespace:
        if type(arguments) == list:
            arguments = shlex.join(arguments)
        
        __iterableArguments = shlex.split(arguments)

        try:
            self.parser = self.setupParser()
            self.options = self.parser.parse_args(__iterableArguments)

        except CommandArgumentParserError as e:
            return None
        
        except SystemExit as e:
            return self.options

        return self.options
        
