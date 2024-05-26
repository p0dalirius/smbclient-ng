#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : InteractiveShell.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


import argparse
import impacket
import ntpath
import shlex
from smbclientng.core.Module import Module
from smbclientng.core.ModuleArgumentParser import ModuleArgumentParser


class Find(Module):
    """
    A class to search for files in a directory hierarchy.

    This class provides functionality to search for files based on various criteria in a directory hierarchy.
    """

    name = "find"
    description = "Search for files in a directory hierarchy"

    def __init__(self, smbSession):
        super(Find, self).__init__(smbSession)
        self.smbSession = smbSession

    def parseArgs(self, arguments):
        parser = ModuleArgumentParser(
            prog=self.name,
            description="Search for files in a directory hierarchy."
        )

        # Adding positional arguments
        parser.add_argument("paths", metavar="PATH", type=str, nargs="*", default=[], help="The starting point(s) for the search.")

        # Adding tests, actions, and options for expressions (incomplete for brevity)
        parser.add_argument("-name", type=str, help="Base of file name (the path with the leading directories removed)")
        parser.add_argument("-iname", type=str, help="Like -name, but the match is case insensitive")
        parser.add_argument("-type", type=str, help="File type (e.g., f for regular file, d for directory)")
        # parser.add_argument("-perm", type=str,  help="File's permission bits")
        parser.add_argument("-size", type=str, help="File uses n units of space")
        parser.add_argument("-mtime", type=str, help="File's data was last modified n*24 hours ago")
        parser.add_argument("-ctime", type=str, help="File's status was last changed n*24 hours ago")
        parser.add_argument("-atime", type=str, help="File was last accessed n*24 hours ago")
        
        # Adding actions
        parser.add_argument("-print", action="store_true", default=False, help="Print the full file name on the standard output")
        parser.add_argument("-ls", action="store_true", default=False, help="List current file in ls -dils format on standard output")
        parser.add_argument("-delete", action="store_true", default=False, help="Delete files; true if removal succeeded")

        # Other options (incomplete for brevity)
        parser.add_argument("-maxdepth", type=int, help="Descend at most levels (a non-negative integer) levels of directories below the command line arguments")
        parser.add_argument("-mindepth", type=int, help="Do not apply any tests or actions at levels less than levels (a non-negative integer)")

        if len(arguments.strip()) == 0:
            parser.print_help()
        else:
            self.options = self.processArguments(parser, arguments)

        if self.options is not None:
            if len(self.options.paths) == 0:
                parser.print_help()

        return self.options

    def __recurse_action(self, base_dir="", paths=[], depth=0):
        for path in paths:
            remote_smb_path = ntpath.normpath(base_dir + ntpath.sep + ntpath.sep.join(path))

            entries = []
            try:
                entries = self.smbSession.smbClient.listPath(
                    shareName=self.smbSession.smb_share, 
                    path=remote_smb_path+'\\*'
                )
            except impacket.smbconnection.SessionError as err:
                return 
            entries = [e for e in entries if e.get_longname() not in [".", ".."]]
            entries = sorted(entries, key=lambda x:x.get_longname())

            # Match and print results
            if self.options.mindepth <= depth <= self.options.maxdepth:
                for entry in entries:
                    if entry.is_directory():
                        print("%s" % ntpath.sep.join(path + [entry.get_longname()]))
                    else:
                        print("%s" % ntpath.sep.join(path + [entry.get_longname()]))

            # 
            for entry in entries:
                if entry.is_directory():
                    self.__recurse_action(
                        base_dir=base_dir, 
                        paths=path+[entry.get_longname()],
                        depth=(depth+1)
                    )

    def run(self, arguments):
        self.options = self.parseArgs(arguments=arguments)

        if self.options is not None:
            # Entrypoint
            try:
                tmp_dir_paths = []
                for path in self.options.paths:
                    tmp_dir_paths.append(
                        ntpath.normpath(self.smbSession.smb_cwd + ntpath.sep + path)
                    )

                self.__recurse_action(
                    base_dir='', 
                    paths=tmp_dir_paths
                )
            except (BrokenPipeError, KeyboardInterrupt) as e:
                print("[!] Interrupted.")
                self.smbSession.close_smb_session()
                self.smbSession.init_smb_session()



