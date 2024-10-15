#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Find.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


import os
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
        parser.add_argument("-q", "--quiet", action="store_true", default=False, help="Suppress normal output.")

        # Adding options for filtering
        parser.add_argument("-name", type=str, help="Base of file name (the path with the leading directories removed).")
        parser.add_argument("-iname", type=str, help="Like -name, but the match is case insensitive.")
        parser.add_argument("-type", type=str, default=None, help="File type (e.g., f for regular file, d for directory).")
        parser.add_argument("-size", type=str, help="File uses n units of space.")
        parser.add_argument('--exclude-dir', action='append', default=[], metavar='DIRNAME[:DEPTH[:CASE]]',
                    help=("Exclude directories matching DIRNAME at specified depth and case sensitivity. "
                          "DEPTH specifies the recursion depth (-1 for all depths, default is 0). "
                          "CASE can be 'i' for case-insensitive or 's' for case-sensitive (default). "
                          "Format: DIRNAME[:DEPTH[:CASE]]"))
        # parser.add_argument("-mtime", type=str, help="File's data was last modified n*24 hours ago")
        # parser.add_argument("-ctime", type=str, help="File's status was last changed n*24 hours ago")
        # parser.add_argument("-atime", type=str, help="File was last accessed n*24 hours ago")

        # Adding actions
        parser.add_argument("-ls", action="store_true", default=False, help="List current file in ls -dils format on standard output.")
        parser.add_argument("-download", action="store_true", default=False, help="List current file in ls -dils format on standard output.")
        parser.add_argument("-o", "--outputfile", type=str, help="Write the names of the files found to the specified file.")

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
    
    def parse_exclude_dirs(self, exclude_dirs):
        """
        Parses the exclude directory arguments and returns a list of exclusion rules.

        Each exclusion rule is a dictionary with keys:
            - 'dirname': The directory name to exclude.
            - 'depth': The depth at which to exclude the directory (-1 for all depths).
            - 'case_sensitive': Boolean indicating if the match is case-sensitive.
        """
        exclusion_rules = []
        for item in exclude_dirs:
            parts = item.split(':')
            dirname = parts[0]
            depth = 0  # Default depth
            case_sensitive = False  # Default to case-insensitive

            # Parse depth if provided
            if len(parts) > 1 and parts[1]:
                try:
                    depth = int(parts[1])
                except ValueError:
                    depth = 0  # Default if depth is invalid

            # Parse case sensitivity if provided
            if len(parts) > 2 and parts[2]:
                case_flag = parts[2].lower()
                if case_flag == 's':
                    case_sensitive = True
                elif case_flag == 'i':
                    case_sensitive = False
                else:
                    # Invalid case flag, default to case-sensitive
                    case_sensitive = True

            exclusion_rules.append({
                'dirname': dirname,
                'depth': depth,
                'case_sensitive': case_sensitive
            })
        return exclusion_rules

    def __find_callback(self, entry, fullpath, depth):
        # Documentation for __find_callback function
        """
        This function serves as a callback for the find operation. It applies filters based on the command line arguments and decides whether to print, download, or list the entry in 'ls -dils' format if it matches the specified filters.

        Args:
            entry (SMBEntry): The current file or directory entry being processed.
            fullpath (str): The full path to the entry.

        The function checks against filters such as file name, case sensitivity, file type, and size. If the entry matches the filters, it will perform actions like printing the entry's details, downloading the entry, or listing the entry based on the options provided in the command line arguments.
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

            # Check the size
            if do_print_entry and self.options.size is not None:
                size_filter = self.options.size
                if (size_filter[1:].isdigit()):
                    size = int(size_filter[1:])
                else:
                    size = int(size_filter[1:-1])
                    units = ["B","K","M","G","T"]
                    if size_filter[-1].upper() in units:
                        size = size * (1024 ** units.index(size_filter[-1]))
                    else:
                        pass

                if size_filter[0] == '+':
                    do_print_entry = entry.get_filesize() >= size
                elif size_filter[0] == '-':
                    do_print_entry = entry.get_filesize() <= size

            if do_print_entry:
                # Actions on matches
                if self.options.download:
                    if entry.is_directory():
                        self.smbSession.get_file_recursively(path=fullpath)
                    else:
                        self.smbSession.get_file(path=fullpath, keepRemotePath=True)
                # Output formats
                output_str = ""
                if self.options.ls:
                    if entry.is_directory():
                        output_str = windows_ls_entry(entry=entry, config=self.config, pathToPrint=fullpath)
                    else:
                        output_str = windows_ls_entry(entry=entry, config=self.config, pathToPrint=fullpath)
                else:
                    if entry.is_directory():
                        output_str = ("%s" % fullpath.replace(ntpath.sep, '/'))
                    else:
                        output_str = ("%s" % fullpath.replace(ntpath.sep, '/'))

                if self.options.outputfile is not None:
                    with open(self.options.outputfile, 'a') as f:
                        f.write(output_str + '\n')

                if not self.options.quiet:
                    print(output_str)

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
            if self.options.outputfile is not None:
                if not os.path.exists(os.path.dirname(self.options.outputfile)):
                    os.makedirs(os.path.dirname(self.options.outputfile))
                open(self.options.outputfile, 'w').close()

            try:
                next_directories_to_explore = []
                for path in list(set(self.options.paths)):
                    next_directories_to_explore.append(ntpath.normpath(path) + ntpath.sep)
                next_directories_to_explore = sorted(list(set(next_directories_to_explore)))

                exclusion_rules = self.parse_exclude_dirs(self.options.exclude_dir)

                self.smbSession.find(
                    paths=next_directories_to_explore,
                    callback=self.__find_callback,
                    exclusion_rules=exclusion_rules
                )

            except (BrokenPipeError, KeyboardInterrupt) as e:
                print("[!] Interrupted.")
                self.smbSession.close_smb_session()
                self.smbSession.init_smb_session()
