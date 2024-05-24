#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : InteractiveShell.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


import datetime
import impacket
import ntpath
import os
import readline
import shutil
import traceback
from rich.console import Console
from rich.table import Table
from smbclient_ng.core.CommandCompleter import CommandCompleter
from smbclient_ng.core.utils import b_filesize, unix_permissions


class InteractiveShell(object):
    """
    Class InteractiveShell is designed to manage the interactive command line interface for smbclient-ng.
    
    This class handles user input, executes commands, and manages the state of the SMB session. It provides
    a command line interface for users to interact with SMB shares, execute commands like directory listing,
    file transfer, and more.

    Attributes:
        smbSession (SMBConnection): The active SMB connection session.
        debug (bool): Flag to enable or disable debug mode.
        smb_share (str): The current SMB share in use.
        smb_path (str): The current path within the SMB share.
        commandCompleterObject (CommandCompleter): Object to handle command completion and help generation.

    Methods:
        __init__(self, smbSession, debug=False): Initializes the InteractiveShell with the given SMB session and debug mode.
        run(self): Starts the command line interface loop, processing user input until exit.
    """
    
    def __init__(self, smbSession, debug=False):
        self.smbSession = smbSession
        self.debug = debug

        self.smb_share = None
        self.smb_cwd = ""

        self.commandCompleterObject = CommandCompleter(smbSession=self.smbSession)
        readline.set_completer(self.commandCompleterObject.complete)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims("\n")

    def run(self):
        running = True
        while running:
            try:
                user_input = input(self.__prompt()).strip().split(" ")
                command, arguments = user_input[0].lower(), user_input[1:]
                
                # Exit the command line
                if command == "exit":
                    running = False

                elif command in self.commandCompleterObject.commands.keys():
                    self.process_command(
                        command=command, 
                        arguments=arguments
                    )

                # Fallback to unknown command
                else:
                    print("Unknown command. Type \"help\" for help.")

            except (KeyboardInterrupt, EOFError) as e:
                print()
                running = False

            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                print("[!] Error: %s" % str(e))

    def process_command(self, command, arguments=[]):
        # Skip
        if command == "":
            pass
        
        # Display help
        elif command == "help":
            # Command arguments required   : No
            # Active SMB connection needed : No
            self.command_help(arguments)

        # Closes the current SMB session
        elif command == "close":
            # Command arguments required   : No
            # Active SMB connection needed : No
            # SMB share needed             : No
            self.command_close(arguments)
        
        # SMB server info
        elif command == "info":
            # Command arguments required   : No
            # Active SMB connection needed : Yes
            # SMB share needed             : No
            if not self.check_smb_connection_available():
                return None
            #
            self.command_info(arguments)
        
        # Reconnects the current SMB session
        elif command in ["reconnect", "connect"]:
            # Command arguments required   : No
            # Active SMB connection needed : No
            # SMB share needed             : No
            self.command_reconnect(arguments)
        
        # Change directory in the current share
        if command == "cd":
            # Command arguments required   : Yes
            # Active SMB connection needed : Yes
            # SMB share needed             : Yes
            if not self.check_command_has_arguments(arguments, command):
                return None
            if not self.check_smb_connection_available():
                return None
            if not self.check_smb_share_is_set():
                return None
            #
            self.command_cd(arguments)

        # Get a file
        elif command == "get":
            # Command arguments required   : Yes
            # Active SMB connection needed : Yes
            # SMB share needed             : Yes
            if not self.check_command_has_arguments(arguments, command):
                return None
            if not self.check_smb_connection_available():
                return None
            if not self.check_smb_share_is_set():
                return None
            #
            self.command_get(arguments)

        # List directory contents in a share
        elif command in ["ls", "dir"]:
            # Command arguments required   : No
            # Active SMB connection needed : Yes
            # SMB share needed             : Yes
            if not self.check_smb_connection_available():
                return None
            if not self.check_smb_share_is_set():
                return None
            #
            self.command_ls(arguments)

        # Creates a new remote directory
        elif command == "mkdir":
            # Command arguments required   : Yes
            # Active SMB connection needed : Yes
            # SMB share needed             : Yes
            if not self.check_command_has_arguments(arguments, command):
                return None
            if not self.check_smb_connection_available():
                return None
            if not self.check_smb_share_is_set():
                return None
            #
            self.command_mkdir(arguments)

        # Put a file
        elif command == "put":
            # Command arguments required   : Yes
            # Active SMB connection needed : Yes
            # SMB share needed             : Yes
            if not self.check_command_has_arguments(arguments, command):
                return None
            if not self.check_smb_connection_available():
                return None
            if not self.check_smb_share_is_set():
                return None
            #
            self.command_put(arguments)

        # Changes the current local directory
        elif command == "lcd":
            # Command arguments required   : Yes
            # Active SMB connection needed : No
            # SMB share needed             : No
            if not self.check_command_has_arguments(arguments, command):
                return None
            #
            self.command_lcd(arguments)

        # Lists the contents of the current local directory
        elif command == "lls":
            # Command arguments required   : Yes
            # Active SMB connection needed : No
            # SMB share needed             : No
            if not self.check_command_has_arguments(arguments, command):
                return None
            #
            self.command_lls(arguments)

        # Creates a new local directory
        elif command == "lmkdir":
            # Command arguments required   : Yes
            # Active SMB connection needed : No
            # SMB share needed             : No
            if not self.check_command_has_arguments(arguments, command):
                return None
            #
            self.command_lmkdir(arguments)

        # Removes a local file
        elif command == "lrm":
            # Command arguments required   : Yes
            # Active SMB connection needed : No
            # SMB share needed             : No
            if not self.check_command_has_arguments(arguments, command):
                return None
            #
            self.command_lrm(arguments)

        # Removes a local directory
        elif command == "lrmdir":
            # Command arguments required   : Yes
            # Active SMB connection needed : No
            # SMB share needed             : No
            if not self.check_command_has_arguments(arguments, command):
                return None
            #
            self.command_lrmdir(arguments)

        # Shows the current local directory
        elif command == "lpwd":
            # Command arguments required   : No
            # Active SMB connection needed : No
            # SMB share needed             : No
            #
            self.command_lpwd(arguments)

        # Removes a remote file
        elif command == "rm":
            # Command arguments required   : Yes
            # Active SMB connection needed : Yes
            # SMB share needed             : Yes
            if not self.check_command_has_arguments(arguments, command):
                return None
            if not self.check_smb_connection_available():
                return None
            if not self.check_smb_share_is_set():
                return None
            #
            self.command_rm(arguments)
            
        # Removes a remote directory
        elif command == "rmdir":
            # Command arguments required   : Yes
            # Active SMB connection needed : Yes
            # SMB share needed             : Yes
            if not self.check_command_has_arguments(arguments, command):
                return None
            if not self.check_smb_connection_available():
                return None
            if not self.check_smb_share_is_set():
                return None
            #
            self.command_rmdir(arguments)

        # List shares
        elif command == "shares":
            # Command arguments required   : No
            # Active SMB connection needed : Yes
            # SMB share needed             : No
            if not self.check_smb_connection_available():
                return None
            #
            self.command_shares(arguments)
        
        # Displays a tree view of the CWD
        elif command == "tree":
            # Command arguments required   : No
            # Active SMB connection needed : Yes
            # SMB share needed             : Yes
            if not self.check_smb_connection_available():
                return None
            if not self.check_smb_share_is_set():
                return None
            #
            self.command_tree(arguments)
        
        # Use a share
        elif command == "use":
            # Command arguments required   : Yes
            # Active SMB connection needed : Yes
            # SMB share needed             : No
            if not self.check_command_has_arguments(arguments, command):
                return None
            if not self.check_smb_connection_available():
                return None
            #
            self.command_use(arguments)

    # Commands ================================================================

    def command_cd(self, arguments):
        path = ' '.join(arguments)
        if self.smbSession.path_isdir(path=path):
            try:
                self.smbSession.set_cwd(path=path)
            except impacket.smbconnection.SessionError as e:
                print("[!] SMB Error: %s" % e)
        else:
            print("[!] Remote path '%s' is not a directory or does not exist." % path)

    def command_close(self):
        self.smbSession.ping_smb_session()
        if self.smbSession.connected:
            self.smbSession.close_smb_session()

    def command_get(self, arguments):
        # Get files recursively
        if arguments[0] == "-r":
            path = ' '.join(arguments[1:]).replace('/', ntpath.sep)
            try:
                self.smbSession.get_file_recursively(path=path)
            except impacket.smbconnection.SessionError as e:
                print("[!] SMB Error: %s" % e)
        # Get a single file
        else:
            path = ' '.join(arguments).replace('/', ntpath.sep)
            try:
                self.smbSession.get_file(path=path)
            except impacket.smbconnection.SessionError as e:
                print("[!] SMB Error: %s" % e)

    def command_help(self, arguments):
        if len(arguments) != 0:
            self.commandCompleterObject.print_help(command=arguments[0])
        else:
            self.commandCompleterObject.print_help(command=None)

    def command_info(self, arguments):
        print_server_info = False
        print_share_info = False
        if len(arguments) != 0:
            print_server_info = (arguments[0].lower() == "server")
            print_share_info = (arguments[0].lower() == "share")
        else:
            print_server_info = True
            print_share_info = True

        try:
            self.smbSession.info(
                share=print_share_info,
                server=print_server_info
            )
        except impacket.smbconnection.SessionError as e:
            print("[!] SMB Error: %s" % e)

    def command_lcd(self, arguments):
        path = ' '.join(arguments)
        if os.path.exists(path=path):
            if os.path.isdir(s=path):
                os.chdir(path=path)
            else:
                print("[!] Path '%s' is not a directory." % path)
        else:
            print("[!] Directory '%s' does not exists." % path)

    def command_lls(self, arguments):
        if len(arguments) == 0:
            directory_contents = os.listdir(path='.')
        else:
            directory_contents = os.listdir(path=' '.join(arguments))

        for entryname in sorted(directory_contents):
            rights_str = unix_permissions(entryname)
            size_str = b_filesize(os.path.getsize(filename=entryname))
            date_str = datetime.datetime.fromtimestamp(os.path.getmtime(filename=entryname)).strftime("%Y-%m-%d %H:%M")

            if os.path.isdir(s=entryname):
                print("%s %10s  %s  \x1b[1;96m%s\x1b[0m%s" % (rights_str, size_str, date_str, entryname, os.path.sep))
            else:
                print("%s %10s  %s  \x1b[1m%s\x1b[0m" % (rights_str, size_str, date_str, entryname))
    
    def command_lmkdir(self, arguments):
        path = ' '.join(arguments)

        # Split each dir
        if os.path.sep in path:
            path = path.strip(os.path.sep).split(os.path.sep)
        else:
            path = [path]

        # Create each dir in the path
        for depth in range(1, len(path)+1):
            tmp_path = os.path.sep.join(path[:depth])
            if not os.path.exists(tmp_path):
                os.mkdir(path=tmp_path)

    def command_lrm(self, arguments):
        path = ' '.join(arguments)
        if os.path.exists(path):
            if not os.path.isdir(s=path):
                try:
                    os.remove(path=path)
                except Exception as e:
                    print("[!] Error removing file '%s' : %s" % path)
            else:
                print("[!] Cannot delete '%s'. It is a directory, use 'lrmdir <directory>' instead." % path)
        else:
            print("[!] Path '%s' does not exist." % path)

    def command_lrmdir(self, arguments):
        path = ' '.join(arguments)
        if os.path.exists(path):
            if os.path.isdir(s=path):
                try:
                    shutil.rmtree(path=path)
                except Exception as e:
                    print("[!] Error removing directory '%s' : %s" % path)
            else:
                print("[!] Cannot delete '%s'. It is a file, use 'lrm <file>' instead." % path)
        else:
            print("[!] Path '%s' does not exist." % path)

    def command_lpwd(self):
        print(os.getcwd())

    def command_ls(self, arguments):
        # Read the files
        directory_contents = self.smbSession.list_contents(path=' '.join(arguments))

        for longname in sorted(directory_contents.keys(), key=lambda x:x.lower()):
            entry = directory_contents[longname]

            meta_string = ""
            meta_string += ("d" if entry.is_directory() else "-")
            meta_string += ("a" if entry.is_archive() else "-")
            meta_string += ("c" if entry.is_compressed() else "-")
            meta_string += ("h" if entry.is_hidden() else "-")
            meta_string += ("n" if entry.is_normal() else "-")
            meta_string += ("r" if entry.is_readonly() else "-")
            meta_string += ("s" if entry.is_system() else "-")
            meta_string += ("t" if entry.is_temporary() else "-")

            size_str = b_filesize(entry.get_filesize())

            date_str = datetime.datetime.fromtimestamp(entry.get_atime_epoch()).strftime("%Y-%m-%d %H:%M")
            
            if entry.is_directory():
                print("%s %10s  %s  \x1b[1;96m%s\x1b[0m\\" % (meta_string, size_str, date_str, longname))
            else:
                print("%s %10s  %s  \x1b[1m%s\x1b[0m" % (meta_string, size_str, date_str, longname))

    def command_mkdir(self, arguments):
        path = ' '.join(arguments)
        self.smbSession.mkdir(path=path)

    def command_put(self, arguments):
        # Put files recursively
        if arguments[0] == "-r":
            localpath = ' '.join(arguments[1:])
            try:
                self.smbSession.put_file_recursively(localpath=localpath)
            except impacket.smbconnection.SessionError as e:
                print("[!] SMB Error: %s" % e)

        # Put a single file
        else:
            localpath = ' '.join(arguments)
            try:
                self.smbSession.put_file(localpath=localpath)
            except impacket.smbconnection.SessionError as e:
                print("[!] SMB Error: %s" % e)

    def command_reconnect(self):
        self.smbSession.ping_smb_session()
        if self.smbSession.connected:
            self.smbSession.close()
            self.smbSession.init_smb_session()
        else:
            self.smbSession.init_smb_session()

    def command_rm(self, arguments):
        path = ' '.join(arguments)
        if self.smbSession.path_exists(path):
            if self.smbSession.path_isfile(path):
                try:
                    self.smbSession.rm(path=path)
                except Exception as e:
                    print("[!] Error removing file '%s' : %s" % path)
            else:
                print("[!] Cannot delete '%s': This is a directory, use 'rmdir <directory>' instead." % path)
        else:
            print("[!] Remote file '%s' does not exist." % path)

    def command_rmdir(self, arguments):
        path = ' '.join(arguments)
        if self.smbSession.path_exists(path):
            if self.smbSession.path_isdir(path):
                try:
                    self.smbSession.rmdir(path=path)
                except Exception as e:
                    print("[!] Error removing directory '%s' : %s" % path)
            else:
                print("[!] Cannot delete '%s': This is a file, use 'rm <file>' instead." % path)
        else:
            print("[!] Remote directory '%s' does not exist." % path)

    def command_shares(self):
        shares = self.smbSession.list_shares()
        if len(shares.keys()) != 0:
            table = Table(title=None)
            table.add_column("Share")
            table.add_column("Hidden")
            table.add_column("Type")
            table.add_column("Description", justify="left")

            for sharename in sorted(shares.keys()):
                is_hidden = bool(sharename.endswith('$'))
                types = ', '.join([s.replace("STYPE_","") for s in shares[sharename]["type"]])
                if is_hidden:
                    table.add_row(sharename, str(is_hidden), types, shares[sharename]["comment"])
                else:
                    table.add_row(sharename, str(is_hidden), types, shares[sharename]["comment"])

            Console().print(table)
        else:
            print("[!] No share served on '%s'" % self.smbSession.address)

    def command_tree(self, arguments):
        if len(arguments) == 0:
            self.smbSession.tree(path='.')
        else:
            self.smbSession.tree(path=' '.join(arguments))

    def command_use(self, arguments):
        sharename = ' '.join(arguments)
        # Reload the list of shares
        shares = self.smbSession.list_shares()
        shares = [s.lower() for s in shares.keys()]
        if sharename.lower() in shares:
            self.smbSession.set_share(sharename)
        else:
            print("[!] No share named '%s' on '%s'" % (sharename, self.smbSession.address))

    # Checks ==================================================================

    def check_smb_connection_available(self):
        self.smbSession.ping_smb_session()
        if self.smbSession.connected:
            return True
        else:
            print("[!] SMB Session is disconnected.")
            return False

    def check_command_has_arguments(self, arguments, command):
        if len(arguments) != 0:
            return True
        else:
            self.commandCompleterObject.print_help(command=command)
            return False

    def check_smb_share_is_set(self):
        if self.smbSession.smb_share is not None:
            return True
        else:
            print("[!] You must open a share first, try the 'use <share>' command.")
            return False

    # Private functions =======================================================

    def __prompt(self):
        self.smbSession.ping_smb_session()
        if self.smbSession.connected:
            connected_dot = "\x1b[1;92m⏺ \x1b[0m"
        else:
            connected_dot = "\x1b[1;91m⏺ \x1b[0m"
        if self.smbSession.smb_share is None:
            str_prompt = "%s[\x1b[1;94m\\\\%s\\\x1b[0m]> " % (connected_dot, self.smbSession.address)
        else:
            str_path = "\\\\%s\\%s\\%s" % (self.smbSession.address, self.smbSession.smb_share, self.smbSession.smb_cwd)
            str_prompt = "%s[\x1b[1;94m%s\x1b[0m]> " % (connected_dot, str_path)
        return str_prompt
