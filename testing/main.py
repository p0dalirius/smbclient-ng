#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : main.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 may 2024


import argparse
import json
import os
import random
import re
import string
import subprocess
import tempfile
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

    def print(self, message="", end='\n'):
        """
        Prints a message to stdout and logs it to a file if logging is enabled.

        This method prints the provided message to the standard output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be printed and logged.
        """

        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print(nocolor_message, end=end)
        else:
            print(message, end=end)
        self.__write_to_logfile(nocolor_message, end=end)

    def info(self, message):
        """
        Logs a message at the INFO level.

        This method logs the provided message at the INFO level. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True. The message is also logged to a file if a log file path is specified during the Logger instance initialization.

        Args:
            message (str): The message to be logged at the INFO level.
        """

        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print("[info] %s" % nocolor_message)
        else:
            print("[\x1b[1;92minfo\x1b[0m] %s" % message)
        self.__write_to_logfile("[info] %s" % nocolor_message)

    def debug(self, message):
        """
        Logs a message at the DEBUG level if debugging is enabled.

        This method logs the provided message at the DEBUG level if the `debug` attribute is set to True during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be logged.
        """
        
        if self._debug == True:
            nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
            if self.no_colors:
                print("[debug] %s" % nocolor_message)
            else:
                print("[debug] %s" % message)
            self.__write_to_logfile("[debug] %s" % nocolor_message)

    def error(self, message):
        """
        Logs an error message to the console and the log file.

        This method logs the provided error message to the standard error output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The error message to be logged.
        """

        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print("[error] %s" % nocolor_message)
        else:
            print("[\x1b[1;91merror\x1b[0m] %s" % message)
        self.__write_to_logfile("[error] %s" % nocolor_message)

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


def find_testCases():
    search_path = os.path.join(os.path.dirname(__file__), "tests")
    tests = {}
    for root, dirs, files in os.walk(search_path):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    tests[file_path] = json.loads(f.read())
    return tests


def render(options, s):
    random_string_8 = ''.join([random.choice(string.ascii_letters + string.digits) for k in range(8)])
    random_string_16 = ''.join([random.choice(string.ascii_letters + string.digits) for k in range(16)])

    output = s.format(
        auth_domain=options.auth_domain,
        auth_username=options.auth_username,
        auth_password=options.auth_password,
        target_host=options.host,
        target_port=options.port,
        random_string=random_string_8,
        random_string_8=random_string_8,
        random_string_16=random_string_16
        # auth_nt_hash=nthash(options.auth_password),
        # auth_lm_hash=lmhash(options.auth_password)
    )

    return output



class Check(object):
    def __init__(self, options, test_case):
        self.options = options
        self.test_case = test_case

    def run(self):
        data = self.exec()     

    def exec(self):
        # Create scriptfile
        startup_script = tempfile.mktemp()
        f = open(startup_script, "w")
        for command in self.test_case["smbclientng_commands"]:
            f.write(render(options, command) + "\n")
        f.close()

        # Create logfile
        logfile = tempfile.mktemp()

        command = [
            "python3", "./smbclient-ng.py", 
            "--startup-script", startup_script,
            "--not-interactive", 
            "--logfile", logfile
        ]
        for flagname, flagvalue in self.test_case["parameters"].items():
            command.append(flagname)
            if flagvalue is not None:
                command.append(render(options, flagvalue))

        l.debug("Executing: %s" % command)
        process = subprocess.Popen(
            args=command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "../")
        )
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            output = stdout.decode('utf-8')
            print("Command output:\n", output)
        else:
            error_output = stderr.decode('utf-8')
            print("Command failed with error:\n", error_output)
        # Cleanup startup_script if still here
        if os.path.exists(startup_script):
            os.remove(startup_script)

    def __print_passed(self):
        print("- %s \x1b[1;48;2;83;170;51;97m PASSED \x1b[0m" % self.test_case["title"])

    def __print_failed(self):
        print("- %s \x1b[1;48;2;233;61;3;97m FAILED \x1b[0m" % self.test_case["title"])


def parseArgs():
    parser = argparse.ArgumentParser(add_help=True, description="")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    parser.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="No colors mode.")
    parser.add_argument("--logfile", dest="logfile", type=str, default=None, help="Output logs to logfile.")

    group_target = parser.add_argument_group("Target")
    group_target.add_argument("--host", action="store", metavar="HOST", required=True, type=str, help="IP address or hostname of the SMB Server to connect to.")  
    group_target.add_argument("--port", action="store", metavar="PORT", type=int, default=445, help="Port of the SMB Server to connect to. (default: 445)")

    authconn = parser.add_argument_group("Authentication & connection")
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", default='.', required=True, help="(FQDN) domain to authenticate to.")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", required=True, help="User to authenticate with.")
    authconn.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", nargs="?", required=True, help="Password to authenticate with.")
    
    return parser.parse_args()


if __name__ == "__main__":
    options = parseArgs()
    l = Logger(no_colors=options.no_colors, debug=options.debug, logfile=options.logfile)

    l.info("Started tests.")
    testCases = find_testCases()
    l.info("Registered %d tests." % len(testCases))

    for pathToTestCase, testCase in testCases.items():
        l.debug("Testing '%s'" % testCase["title"])
        c = Check(test_case=testCase, options=options)
        c.run()

    l.info("Finished tests.")