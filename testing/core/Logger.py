#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Logger.py
# Author             : Podalirius (@podalirius_)
# Date created       : 09 july 2024


import datetime
import os
import re
from enum import Enum


class LogLevel(Enum):
    INFO = 1
    DEBUG = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5


class Logger(object):
    """
    A Logger class that provides logging functionalities with various levels such as INFO, DEBUG, WARNING, ERROR, and CRITICAL.
    It supports color-coded output, which can be disabled, and can also log messages to a file.

    Attributes:
        __debug (bool): If True, debug level messages will be printed and logged.
        __nocolors (bool): If True, disables color-coded output.
        logfile (str|None): Path to a file where logs will be written. If None, logging to a file is disabled.

    Methods:
        __init__(debug=False, logfile=None, nocolors=False): Initializes the Logger instance.
        print(message=""): Prints a message to stdout and logs it to a file if logging is enabled.
        info(message): Logs a message at the INFO level.
        debug(message): Logs a message at the DEBUG level if debugging is enabled.
        error(message): Logs a message at the ERROR level.
    """

    def __init__(self, no_colors, logfile=None, debug=False):
        super(Logger, self).__init__()
        self.no_colors = no_colors
        self.logfile = logfile
        self._debug = debug
        #
        if self.logfile is not None:
            if os.path.exists(self.logfile):
                k = 1
                while os.path.exists(self.logfile+(".%d"%k)):
                    k += 1
                self.logfile = self.logfile + (".%d" % k)
            open(self.logfile, "w").close()

    def print(self, message="", end='\n', date=True):
        """
        Prints a message to stdout and logs it to a file if logging is enabled.

        This method prints the provided message to the standard output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be printed and logged.
        """

        if date:
            datestr = datetime.datetime.now().strftime("[%Y-%m-%d %Hh%Mm%Ss] ")
        else:
            datestr = ""

        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print(f"{datestr}{nocolor_message}", end=end)
        else:
            print(f"{datestr}{message}", end=end)
        self.__write_to_logfile(nocolor_message, end=end)

    def info(self, message):
        """
        Logs a message at the INFO level.

        This method logs the provided message at the INFO level. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True. The message is also logged to a file if a log file path is specified during the Logger instance initialization.

        Args:
            message (str): The message to be logged at the INFO level.
        """

        datestr = datetime.datetime.now().strftime("[%Y-%m-%d %Hh%Mm%Ss]")     

        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print(f"{datestr} [info] {nocolor_message}")
        else:
            print(f"{datestr} [\x1b[1;92minfo\x1b[0m] {nocolor_message}")
        self.__write_to_logfile(f"{datestr} [info] %s" % nocolor_message)

    def debug(self, message):
        """
        Logs a message at the DEBUG level if debugging is enabled.

        This method logs the provided message at the DEBUG level if the `debug` attribute is set to True during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be logged.
        """

        datestr = datetime.datetime.now().strftime("[%Y-%m-%d %Hh%Mm%Ss]")
        
        if self._debug == True:
            nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
            if self.no_colors:
                print(f"{datestr} [debug] {nocolor_message}")
            else:
                print(f"{datestr} [debug] %s" % message)
            self.__write_to_logfile(f"{datestr} [debug] %s" % nocolor_message)

    def error(self, message):
        """
        Logs an error message to the console and the log file.

        This method logs the provided error message to the standard error output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The error message to be logged.
        """

        datestr = datetime.datetime.now().strftime("[%Y-%m-%d %Hh%Mm%Ss]")

        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print(f"{datestr} [error] {nocolor_message}")
        else:
            print(f"{datestr} [\x1b[1;91merror\x1b[0m] %s" % message)
        self.__write_to_logfile(f"{datestr} [error] %s" % nocolor_message)

    def __write_to_logfile(self, message, end='\n'):
        """
        Writes the provided message to the log file specified during Logger instance initialization.

        This method appends the provided message to the log file specified by the `logfile` attribute. If no log file path is specified, this method does nothing.

        Args:
            message (str): The message to be written to the log file.
        """

        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write(message + end)
            f.close()

