#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ModuleArgumentParser.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


import argparse
import sys

class ModuleArgumentParserError(Exception):
    def __init__(self,  message):
        self.message = message

    def __str__(self):
        return self.message
class ModuleArgumentParser(argparse.ArgumentParser):
    """
    A custom argument parser for handling module-specific command-line arguments in the smbclientng application.

    This class extends the argparse.ArgumentParser and provides custom error handling specific to the needs of smbclientng modules.
    It is designed to provide clear and user-friendly command-line interfaces for various modules within the smbclientng suite.

    Attributes:
        None

    Methods:
        error(message: str):
            Overrides the default error handling to provide a more informative error message and display the help text.
    """

    exit_on_error: bool = False

    def error(self, message: str):
        """
        Overrides the default error handling of argparse.ArgumentParser to provide a custom error message and help display.

        This method is called when ArgumentParser encounters an error. It displays the help message and writes the error message 
        to stderr.        

        Args:
            message (str): The error message to be displayed.
        """

        self.print_help()
        sys.stderr.write('\n[!] Error: %s\n' % message)
        raise ModuleArgumentParserError(message)
