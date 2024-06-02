#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : InteractiveShell.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


import impacket
import ntpath
import re
from smbclientng.core.Module import Module
from smbclientng.core.ModuleArgumentParser import ModuleArgumentParser
from smbclientng.core.utils import windows_ls_entry


class Find(Module):
    """
    A class to search for files in a directory hierarchy.

    This class provides functionality to search for files based on various criteria in a directory hierarchy.
    """

    name = "find"
    description = "Search for files in a directory hierarchy"

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

        # Adding options for filtering
        parser.add_argument("-name", type=str, help="Base of file name (the path with the leading directories removed).")
        parser.add_argument("-iname", type=str, help="Like -name, but the match is case insensitive.")
        parser.add_argument("-type", type=str, default=None, help="File type (e.g., f for regular file, d for directory).")
        parser.add_argument("-size", type=str, help="File uses n units of space.")
        # parser.add_argument("-mtime", type=str, help="File's data was last modified n*24 hours ago")
        # parser.add_argument("-ctime", type=str, help="File's status was last changed n*24 hours ago")
        # parser.add_argument("-atime", type=str, help="File was last accessed n*24 hours ago")
        
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

        if self.options is not None:
            if len(self.options.paths) == 0:
                parser.print_help()
                self.options = None

        return self.options

    def __find_callback(self, entry, fullpath, depth):
        # Documentation for __find_callback function
        """
        This function serves as a callback for the find operation. It applies filters based on the command line arguments
        and decides whether to print, download, or list the entry in 'ls -dils' format if it matches the specified filters.

        Args:
            entry (SMBEntry): The current file or directory entry being processed.
            fullpath (str): The full path to the entry.

        The function checks against filters such as file name, case sensitivity, file type, and size. If the entry matches
        the filters, it will perform actions like printing the entry's details, downloading the entry, or listing the entry
        based on the options provided in the command line arguments.
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
            do_print_entry = False
            # Print directory
            if entry.is_directory():
                if (self.options.type == 'd' or self.options.type is None):
                    # No name filtering
                    if self.options.name is None and self.options.iname is None:
                        do_print_entry = True
                    
                    # Filtering on names case sensitive
                    elif self.options.name is not None:
                        if '*' in self.options.name:
                            regex = self.options.name
                            regex = regex.replace('.', '\\.')
                            regex = regex.replace('*', '.*')
                            regex = '^' + regex + '$'
                            if re.match(regex, entry.get_longname()):
                                do_print_entry = True
                            else:
                                do_print_entry = False
                        else:
                            do_print_entry = (entry.get_longname().lower() == self.options.name.lower())
                    
                    # Filtering on names case insensitive  
                    elif self.options.iname is not None:
                        if '*' in self.options.iname:
                            regex = self.options.iname
                            regex = regex.replace('.', '\\.')
                            regex = regex.replace('*', '.*')
                            regex = '^' + regex + '$'
                            if re.match(regex, entry.get_longname(), re.IGNORECASE):
                                do_print_entry = True
                            else:
                                do_print_entry = False
                        else:
                            do_print_entry = (entry.get_longname().lower() == self.options.iname.lower())
                            
            # Print file
            else:
                if (self.options.type == 'f' or self.options.type is None):
                    # No name filtering
                    if self.options.name is None and self.options.iname is None:
                        do_print_entry = True
                    
                    # Filtering on names case sensitive
                    elif self.options.name is not None:
                        if '*' in self.options.name:
                            regex = self.options.name
                            regex = regex.replace('.', '\\.')
                            regex = regex.replace('*', '.*')
                            regex = '^' + regex + '$'
                            if re.match(regex, entry.get_longname()):
                                do_print_entry = True
                            else:
                                do_print_entry = False
                        else:
                            do_print_entry = (entry.get_longname().lower() == self.options.name.lower())
                    
                    # Filtering on names case insensitive
                    elif self.options.iname is not None:
                        if '*' in self.options.iname:
                            regex = self.options.iname
                            regex = regex.replace('.', '\\.')
                            regex = regex.replace('*', '.*')
                            regex = '^' + regex + '$'
                            if re.match(regex, entry.get_longname(), re.IGNORECASE):
                                do_print_entry = True
                            else:
                                do_print_entry = False
                        else:
                            do_print_entry = (entry.get_longname().lower() == self.options.iname.lower())

            if do_print_entry:
                # Actions on matches
                if self.options.download:
                    if entry.is_directory():
                        self.smbSession.get_file_recursively(path=fullpath)
                    else:
                        self.smbSession.get_file(path=fullpath, keepRemotePath=True)
                # Output formats
                if self.options.ls:
                    if entry.is_directory():
                        windows_ls_entry(entry, fullpath)
                    else:
                        windows_ls_entry(entry, fullpath)
                else:
                    if entry.is_directory():
                        print("%s" % fullpath)
                    else:
                        print("%s" % fullpath)
                        
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



