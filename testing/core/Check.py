#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Check.py
# Author             : Podalirius (@podalirius_)
# Date created       : 09 july 2024


import os
import subprocess
import tempfile
from .utils import render, parseLogfileContents


class Check(object):

    def __init__(self, logger, options, test_case):
        self.logger = logger
        self.options = options
        self.test_case = test_case

    def run(self):
        data = self.exec()
        parsed = parseLogfileContents(data)
        last_line = parsed[-1]

        check_passed = True
        for expectedMessage in self.test_case["expected_output"]["messages"]:
            if expectedMessage not in ''.join(last_line["output"]):
                check_passed = False
            else:
                self.logger.debug("'%s' is not present in output" % expectedMessage)

        # Error output is matching what is expected
        if self.test_case["expected_output"]["error"] != last_line["error"]:
            self.logger.debug("Error output is not matching what is expected.")
            check_passed = False

        # Traceback output is matching what is expected
        if self.test_case["expected_output"]["traceback"] != last_line["traceback"]:
            self.logger.debug("Traceback output is not matching what is expected.")
            check_passed = False
        
        # Final print of check
        if check_passed:
            self.__print_passed()
        else:
            self.__print_failed()

    def exec(self):
        # Create scriptfile
        startup_script = tempfile.mktemp()
        f = open(startup_script, "w")
        for command in self.test_case["smbclientng_commands"]:
            f.write(render(self.options, command) + "\n")
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
                command.append(render(self.options, flagvalue))

        self.logger.debug("Executing: %s" % command)
        process = subprocess.Popen(
            args=command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "..", "..")
        )
        stdout, stderr = process.communicate()

        # Cleanup startup_script if still here
        if os.path.exists(startup_script):
            os.remove(startup_script)

        if process.returncode == 0:
            if os.path.exists(logfile):
                with open(logfile, 'r') as log:
                    log_contents = log.read()
                return log_contents
            else:
                self.logger.debug("Log file '%s' does not exist." % logfile)
                return None
        else:
            print(stderr.decode('utf-8'))
            self.logger.debug("Process returned '%d'." % process.returncode)
            return None
    
    def __print_passed(self):
        title = (self.test_case["title"]+" ").ljust(60,'─')
        self.logger.print("├───┼───┼── %s \x1b[1;48;2;83;170;51;97m PASSED \x1b[0m" % title)

    def __print_failed(self):
        title = (self.test_case["title"]+" ").ljust(60,'─')
        self.logger.print("├───┼───┼── %s \x1b[1;48;2;233;61;3;97m FAILED \x1b[0m" % title)

