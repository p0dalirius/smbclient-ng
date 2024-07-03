#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Users.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


from smbclientng.core.Module import Module
from smbclientng.core.ModuleArgumentParser import ModuleArgumentParser


class Users(Module):

    name = "users"
    description = "Detects habits of users by the presence of cache files."

    users_directory = "/Users"

    checks = {
        "browser": {
            "name": "Browser Profiles",
            "checks": {
                "Brave": "/{users_directory}/{user}/AppData/Local/BraveSoftware/",
                "Google Chrome": "/{users_directory}/{user}/AppData/Local/Google/Chrome/",
                "Microsoft Edge": "/{users_directory}/{user}/AppData/Local/Microsoft/Edge/",
                "Mozilla Firefox": "/{users_directory}/{user}/AppData/Local/Mozilla/Firefox/",
                "Opera": "/{users_directory}/{user}/AppData/Local/Opera Software/",
                "Safari": "/{users_directory}/{user}/AppData/Local/Apple Computer/Safari/"
            }
        },
        "email": {
            "name": "Email Clients",
            "checks": {
                "Microsoft Outlook": "/{users_directory}/{user}/AppData/Local/Microsoft/Outlook/",
                "Mozilla Thunderbird": "/{users_directory}/{user}/AppData/Local/Mozilla/Thunderbird/",
                "Windows Mail": "/{users_directory}/{user}/AppData/Local/Microsoft/Windows Mail/"
            }
        },
        "productivity": {
            "name": "Productivity Software",
            "checks": {
                "Microsoft Office": "/{users_directory}/{user}/AppData/Local/Microsoft/Office/",
                "LibreOffice": "/{users_directory}/{user}/AppData/Local/LibreOffice/",
                "OpenOffice": "/{users_directory}/{user}/AppData/Local/OpenOffice/",
                "ShareX": "/{users_directory}/{user}/Documents/ShareX/Screenshots/"
            }
        }
    }

    def parseArgs(self, arguments):
        """
        Parses the command line arguments provided to the module.

        This method initializes the argument parser with the module's name and description, and defines all the necessary arguments that the module accepts. It then parses the provided command line arguments based on these definitions.

        Args:
            arguments (str): A string of command line arguments.

        Returns:
            ModuleArgumentParser.Namespace | None: The parsed arguments as a Namespace object if successful, None if there are no arguments or help is requested.
        """

        parser = ModuleArgumentParser(prog=self.name, description=self.description)

        parser.add_argument("-d", "--users-directory", dest="users_directory", default="/Users", help="Specify the directory where user home directories are located.")
        parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose mode.")
    
        self.options = self.processArguments(parser, arguments)

        return self.options

    def getListOfUsersHomes(self):
        """
        Retrieves a list of user home directories from the SMB share.

        This method connects to the SMB share, navigates to the Users directory, and lists all subdirectories. It then filters out the current directory (.) and parent directory (..) to only include actual user home directories. The method returns a list of user home directory names.

        Returns:
            list: A list of user home directory names.
        """

        old_share = self.smbSession.smb_share
        old_pwd = self.smbSession.smb_cwd

        users = []
        self.smbSession.set_share('C$')
        if self.smbSession.path_isdir(self.users_directory):
            self.smbSession.set_cwd(self.users_directory)
            for entryname, entry in self.smbSession.list_contents("").items():
                if (entry.get_longname() not in [".",".."]) and (entry.is_directory()):
                    users.append(entry.get_longname())

        self.smbSession.set_share(old_share)
        self.smbSession.set_cwd(old_pwd)

        return users

    #=[Browser]====================================================================

    def perform_checks(self, user):
        for category_key in self.checks.keys():
            category = self.checks[category_key]
            at_least_one_found = False
            for check_name, check_path in category["checks"].items():
                check_path = check_path.format(user=user, users_directory=self.users_directory)
                if self.smbSession.path_isdir(pathFromRoot=check_path):
                    if not at_least_one_found:
                        print("  ├──> %s:" % category["name"])
                        at_least_one_found = True
                    print("  │  ├──> \x1b[92muses '%s'\x1b[0m" % (check_name))
                elif self.options.verbose:
                    print("  │  ├──> \x1b[91mdoes not use '%s'\x1b[0m" % (check_name))

    #=[Run]====================================================================

    def run(self, arguments):
        self.options = self.parseArgs(arguments=arguments)

        if self.options is not None:
            self.users_directory = self.options.users_directory
            # Entrypoint
            try:
                users = self.getListOfUsersHomes()
                for user in users:
                    print("[+] Analyzing user: '%s'" % user)
                    self.perform_checks(user=user)

            except (BrokenPipeError, KeyboardInterrupt) as e:
                print("[!] Interrupted.")
                self.smbSession.close_smb_session()
                self.smbSession.init_smb_session()



