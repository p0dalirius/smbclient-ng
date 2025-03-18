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
from smbclientng.utils.utils import windows_ls_entry, smb_entry_iterator


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
        parser.add_argument("-name", action='append', help="Base of file name (the path with the leading directories removed).")
        parser.add_argument("-iname", action='append', help="Like -name, but the match is case insensitive.")
        parser.add_argument("-type", type=str, default=None, help="File type (e.g., f for regular file, d for directory).")
        parser.add_argument("-size", type=str, help="File uses n units of space.")
        parser.add_argument('--exclude-dir', action='append', default=[], metavar='DIRNAME[:DEPTH[:CASE]]',
                    help=("Exclude directories matching DIRNAME until specified depth and case sensitivity. "
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

        if not arguments.strip():
            parser.print_help()
            return None
        else:
            # Parse the arguments safely
            try:
                args = parser.parse_args(arguments.split())
            except SystemExit:
                # argparse uses sys.exit(), which raises SystemExit
                return None

            # Check if paths are provided; if not, print help and exit
            if not args.paths:
                parser.print_help()
                return None

            self.options = args

        return self.options
    
    def parse_exclude_dirs(self, exclude_dirs):
        """
        Parses the exclude directory arguments and returns a list of exclusion rules.

        Each exclusion rule is a dictionary with keys:
            - 'dirname': The directory name to exclude.
            - 'depth': The depth until which to exclude the directory (-1 for all depths).
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

    def run(self, arguments):
        self.options = self.parseArgs(arguments=arguments)

        if self.options is not None:
            # Prepare output file
            if self.options.outputfile is not None:
                os.makedirs(os.path.dirname(self.options.outputfile), exist_ok=True)
                open(self.options.outputfile, 'w').close()

            try:
                exclusion_rules = self.parse_exclude_dirs(self.options.exclude_dir)
                start_paths = self.options.paths or [self.smbSession.smb_cwd]

                # Prepare filters
                filters = {}
                if self.options.type:
                    filters['type'] = self.options.type
                if self.options.name:
                    filters['name'] = self.options.name
                if self.options.iname:
                    filters['iname'] = self.options.iname
                if self.options.size:
                    filters['size'] = self.options.size

                generator = smb_entry_iterator(
                    smb_client=self.smbSession.smbClient,
                    smb_share=self.smbSession.smb_share,
                    start_paths=start_paths,
                    exclusion_rules=exclusion_rules,
                    max_depth=self.options.maxdepth,
                    min_depth=self.options.mindepth or 0,
                    filters=filters
                )

                for entry, fullpath, depth, is_last_entry in generator:
                    # Actions on matches
                    if self.options.download:
                        if not entry.is_directory():
                            self.smbSession.get_file(path=fullpath, keepRemotePath=True)
                    # Output formats
                    output_str = ""
                    if self.options.ls:
                        output_str = windows_ls_entry(entry=entry, config=self.config, pathToPrint=fullpath)
                    else:
                        output_str = fullpath.replace(ntpath.sep, '/')

                    if self.options.outputfile is not None:
                        with open(self.options.outputfile, 'a') as f:
                            f.write(output_str + '\n')

                    if not self.options.quiet and not self.options.download:
                        print(output_str)

            except (BrokenPipeError, KeyboardInterrupt):
                print("[!] Interrupted.")
                self.smbSession.close_smb_session()
                self.smbSession.init_smb_session()
