#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : InteractiveShell.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


import shlex


class Module(object):
    """
    A parent class for all modules in the smbclient-ng tool.

    This class provides common attributes and methods that are shared among different modules.
    """

    name = ""
    description = ""
    smbSession = None
    options = None

    def __init__(self, smbSession, config, logger):
        self.smbSession = smbSession
        self.config = config
        self.logger = logger

    def parseArgs(self):
        raise NotImplementedError("Subclasses must implement this method")

    def run(self):
        """
        Placeholder method for running the module.

        This method should be implemented by subclasses to define the specific behavior of the module.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def processArguments(self, parser, arguments):
        if type(arguments) == list:
            arguments = ' '.join(arguments)
        
        __iterableArguments = shlex.split(arguments)

        try:
            self.options = parser.parse_args(__iterableArguments)
        except SystemExit as e:
            pass

        return self.options
        
