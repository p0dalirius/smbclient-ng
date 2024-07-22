#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : main.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 may 2024


import argparse
from core.Logger import Logger
from core.Check import Check
from core.utils import find_testCases


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
    logger = Logger(no_colors=options.no_colors, debug=options.debug, logfile=options.logfile)

    logger.info("Started tests.")
    testCases = find_testCases()
    nb_testcases = 0
    for category in sorted(testCases.keys()):
        for subcategory in sorted(testCases[category].keys()):
            nb_testcases += len(testCases[category][subcategory].keys())
    logger.info("Registered %d tests." % nb_testcases)


    tests_passed = 0
    tests_failed = 0
    for category in sorted(testCases.keys()):
        logger.print("\x1b[1;48;2;170;170;170;30m├──[+] Category: %-84s\x1b[0m" % category)

        for subcategory in sorted(testCases[category].keys()):
            logger.print("\x1b[1;48;2;200;200;200;30m├───┼──[+] Subcategory: %-77s\x1b[0m" % subcategory)

            for pathToTestCase, testCase in testCases[category][subcategory].items():
                logger.debug("Testing: %s" % testCase["title"])
                c = Check(logger=logger, options=options, test_case=testCase)
                
                if c.run() == True:
                    tests_passed += 1
                else:
                    tests_failed += 1

    logger.print("\x1b[1;48;2;170;170;170;30m[+] %-96s \x1b[0m" % "All done!")
    logger.info("Finished tests.")
    logger.info("Tests PASSED: (%d/%d) %d%%" % (tests_passed, nb_testcases, (tests_passed / nb_testcases)*100))
    logger.info("Tests FAILED: (%d/%d) %d%%" % (tests_failed, nb_testcases, (tests_failed / nb_testcases)*100))