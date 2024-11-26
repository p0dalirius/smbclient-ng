#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : InteractiveShell.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024

from __future__ import annotations
import charset_normalizer
import datetime
from impacket.smb3structs import *
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.smb3 import SessionError as SMB3SessionError
from importlib import import_module
import impacket.smbconnection
from impacket.smb3structs import *
import ntpath
import os
import readline
import shutil
import shlex
import sys
import traceback
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from smbclientng.core.CommandCompleter import CommandCompleter
from smbclientng.core.utils import b_filesize, unix_permissions, windows_ls_entry, local_tree, resolve_local_files, resolve_remote_files, smb_entry_iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smbclientng.core.SessionsManager import SessionsManager
    from smbclientng.core.Config import Config
    from smbclientng.core.Logger import Logger

## Decorators

def command_arguments_required(func):
    def wrapper(*args, **kwargs):
        self, arguments,command  = args[0], args[1], args[2]
        if len(arguments) != 0:
            return func(*args, **kwargs)
        else:
            self.commandCompleterObject.print_help(command=command)
            return None
    return wrapper

def active_smb_connection_needed(func):
    def wrapper(*args, **kwargs):
        self, arguments,command  = args[0], args[1], args[2]
        
        if self.sessionsManager.current_session is None:
            self.logger.error("SMB Session is disconnected.")
            return None

        self.sessionsManager.current_session.ping_smb_session()
        if self.sessionsManager.current_session.connected:
            return func(*args, **kwargs)
        else:
            self.logger.error("SMB Session is disconnected.")
            return None
    return wrapper

def smb_share_is_set(func):
    def wrapper(*args, **kwargs):
        self, arguments,command  = args[0], args[1], args[2]
        if self.sessionsManager.current_session.smb_share is not None:
            return func(*args, **kwargs)
        else:
            self.logger.error("You must open a share first, try the 'use <share>' command.")
            return None
    return wrapper


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

    running = True
    modules = {}
    sessionsManager: SessionsManager
    config: Config
    logger: Logger
    commandCompleterObject: CommandCompleter
    
    def __init__(self, sessionsManager: SessionsManager, config: Config, logger: Logger):
        # Objects
        self.sessionsManager = sessionsManager
        self.config = config
        self.logger = logger
        # Internals
        self.commandCompleterObject = CommandCompleter(
            smbSession=self.sessionsManager.current_session,
            config=self.config,
            logger=self.logger,
        )
        readline.set_completer(self.commandCompleterObject.complete)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims("\n")
        # Additional modules
        self.__load_modules()

    def run(self):
        # Read commands from script file first
        if self.config.startup_script:
            f = open(self.config.startup_script, 'r')
            for line in f.readlines():
                try:
                    self.logger.print("%s%s" % (self.__prompt(), line.strip()))
                    readline.add_history(line.strip())
                    self.process_line(commandLine=line.strip())
                except KeyboardInterrupt as e:
                    self.logger.print()

                except EOFError as e:
                    self.logger.print()
                    running = False

                except Exception as err:
                    if self.config.debug:
                        traceback.print_exc()
                    self.logger.error(str(err))

        # Then interactive console
        if not self.config.not_interactive:
            while self.running:
                try:
                    user_input = input(self.__prompt()).strip()
                    self.logger.write_to_logfile(self.__prompt() + user_input)
                    self.process_line(commandLine=user_input)
                except KeyboardInterrupt as e:
                    self.logger.print()

                except EOFError as e:
                    self.logger.print()
                    running = False

                except Exception as err:
                    if self.config.debug:
                        traceback.print_exc()
                    self.logger.error(str(err))

    def process_line(self, commandLine: str):
        # Split and parse the commandLine
        tokens = shlex.split(commandLine)
        if len(tokens) == 0:
            command = ""
            arguments = []
        elif len(tokens) == 1:
            command = tokens[0].lower()
            arguments = []
        else:
            command = tokens[0].lower()
            arguments = tokens[1:]
        
        # Skip
        if command.strip() == "":
            pass
        # Execute the command
        elif command in self.commandCompleterObject.commands.keys():

            # Exit the command line
            if command in ["exit", "quit"]:
                self.running = False
            
            # Display help
            elif command == "help":
                self.command_help(arguments, command)

            # Cat the contents of a file
            elif command == "bat":
                self.command_bat(arguments, command)

            # Cat the contents of a file
            elif command == "cat":
                self.command_cat(arguments, command)

            # Closes the current SMB session
            elif command == "close":
                self.command_close(arguments, command)
                
            # Change directory in the current share
            elif command == "cd":
                self.command_cd(arguments, command)
            
            # debug
            elif command == "debug":
                self.command_debug(arguments, command)
            
            # Find
            elif command == "find":
                self.command_find(arguments, command)

            # Get a file
            elif command == "get":
                self.command_get(arguments, command)

            # SMB server info
            elif command == "info":
                self.command_info(arguments, command)

            # List directory contents in a share
            elif command in ["ls", "dir"]:
                self.command_ls(arguments, command)

            # List directory contents in a share
            elif command in ["acls"]:
                self.command_acls(arguments, command)

            # Shows the content of a local file
            elif command == "lcat":
                self.command_lcat(arguments, command)

            # Changes the current local directory
            elif command == "lcd":
                self.command_lcd(arguments, command)

            # Creates a copy of a local file
            elif command == "lcp":
                self.command_lcp(arguments, command)

            # Pretty prints the content of a local file
            elif command == "lbat":
                self.command_lbat(arguments, command)

            # Lists the contents of the current local directory
            elif command == "lls":
                self.command_lls(arguments, command)

            # Creates a new local directory
            elif command == "lmkdir":
                self.command_lmkdir(arguments, command)

            # Shows the current local directory
            elif command == "lpwd":
                self.command_lpwd(arguments, command)

            # Renames a local file
            elif command == "lrename":
                self.command_lrename(arguments, command)
            
            # Removes a local file
            elif command == "lrm":
                self.command_lrm(arguments, command)

            # Removes a local directory
            elif command == "lrmdir":
                self.command_lrmdir(arguments, command)

            # Shows the current local directory
            elif command == "ltree":
                self.command_ltree(arguments, command)

            # Creates a new remote directory
            elif command == "mkdir":
                self.command_mkdir(arguments, command)

            # Modules
            elif command == "module":
                self.command_module(arguments, command)

            # Creates a mount point of the remote share on the local machine
            elif command == "mount":
                self.command_mount(arguments, command)

            # Put a file
            elif command == "put":
                self.command_put(arguments, command)

            # Reconnects the current SMB session
            elif command in ["connect", "reconnect"]:
                self.command_reconnect(arguments, command)

            # Reset the TTY output
            elif command == "reset":
                self.command_reset(arguments, command)

            # Removes a remote file
            elif command == "rm":
                self.command_rm(arguments, command)
                
            # Removes a remote directory
            elif command == "rmdir":
                self.command_rmdir(arguments, command)

            # Sessions management
            elif command == "sessions":
                self.sessionsManager.process_command_line(arguments)

            # List shares
            elif command == "sizeof":
                self.command_sizeof(arguments, command)

            # List shares
            elif command == "shares":
                self.command_shares(arguments, command)
            
            # Displays a tree view of the CWD
            elif command == "tree":
                self.command_tree(arguments, command)
            
            # Use a share
            elif command == "use":
                self.command_use(arguments, command)
        
        # Fallback to unknown command   
        else:
            self.logger.print("Unknown command. Type \"help\" for help.")

    # Commands ================================================================

    def command_debug(self, arguments: list[str], command: str):
        try:
            self.logger.print("[debug] command    = '%s'" % command)
            self.logger.print("[debug] arguments  = %s" % arguments)
        except Exception as e:
            traceback.print_exc()


    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_bat(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        # Parse wildcards
        files_and_directories = resolve_remote_files(self.sessionsManager.current_session, arguments)

        for path_to_file in files_and_directories:
            if self.sessionsManager.current_session.path_isfile(pathFromRoot=path_to_file):
                # Read the file
                try:    
                    rawcontents = self.sessionsManager.current_session.read_file(path=path_to_file)
                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]
                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            lexer = Syntax.guess_lexer(path=ntpath.basename(path_to_file), code=filecontent)
                            # Some trickery for the files undetected by the lexer
                            if lexer == "default":
                                if '<?xml' in filecontent:
                                    lexer = "xml"
                                elif '<html>' in filecontent:
                                    lexer = "html"
                            syntax = Syntax(code=filecontent, line_numbers=True, lexer=lexer)
                            if len(files_and_directories) > 1:
                                self.logger.print("\x1b[1;93m[>] %s\x1b[0m" % (path_to_file+' ').ljust(80,'='))
                            Console().print(syntax)
                        else:
                            self.logger.error("[!] Could not detect charset of '%s'." % path_to_file)
                except SMBConnectionSessionError as e:
                    self.logger.error("[!] SMB Error: %s" % e)

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_cd(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        try:
            self.sessionsManager.current_session.set_cwd(path=arguments[0])
        except SMBConnectionSessionError as e:
            self.logger.error("[!] SMB Error: %s" % e)

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_cat(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        # Parse wildcards
        files_and_directories = resolve_remote_files(self.sessionsManager.current_session, arguments)

        for path_to_file in files_and_directories:
            if self.sessionsManager.current_session.path_isfile(pathFromRoot=path_to_file):
                # Read the file
                try:
                    rawcontents = self.sessionsManager.current_session.read_file(path=path_to_file)
                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]
                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            if len(files_and_directories) > 1:
                                self.logger.print("\x1b[1;93m[>] %s\x1b[0m" % (path_to_file+' ').ljust(80,'='))
                            self.logger.print(filecontent)
                        else:
                            self.logger.error("[!] Could not detect charset of '%s'." % path_to_file)
                except SMBConnectionSessionError as e:
                    self.logger.error("[!] SMB Error: %s" % e)

    def command_close(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.sessionsManager.current_session.ping_smb_session()
        if self.sessionsManager.current_session.connected:
            self.sessionsManager.current_session.close_smb_session()

    def command_find(self, arguments: list[str], command: str):
        module_name = "find"

        if module_name in self.modules.keys():
            module = self.modules[module_name](self.sessionsManager.current_session, self.config, self.logger)
            arguments_string = ' '.join(arguments)
            module.run(arguments_string)
        else:
            self.logger.error("Module '%s' does not exist." % module_name)

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_get(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        is_recursive = False
        keep_remote_path = False  
        # Parse '-r' option
        while '-r' in arguments:
            is_recursive = True
            arguments.remove('-r')
        
        # Parse '-k' option for keepRemotePath if you have it
        while '-k' in arguments:
            keep_remote_path = True
            arguments.remove('-k')

        # Handle 'get -r' with no other argument
        if len(arguments) == 0:
            arguments = ['*']

        # Parse wildcards
        files_and_directories = resolve_remote_files(self.sessionsManager.current_session, arguments)

        # Download files/directories
        for remotepath in files_and_directories:
            try:
                self.sessionsManager.current_session.get_file(
                    path=remotepath,
                    keepRemotePath=keep_remote_path,
                    is_recursive=is_recursive
                )
            except SMBConnectionSessionError as e:
                if self.config.debug:
                    traceback.print_exc()
                self.logger.error("[!] SMB Error: %s" % e)

    def command_help(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) != 0:
            self.commandCompleterObject.print_help(command=arguments[0])
        else:
            self.commandCompleterObject.print_help(command=None)

    @active_smb_connection_needed
    def command_info(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : No

        print_server_info = False
        print_share_info = False
        if len(arguments) != 0:
            if arguments[0].lower() not in ["server", "share"]:
                self.logger.error("'%s' is not a valid parameter. Use 'server' or 'share'." % arguments[0])
                return None
            print_server_info = (arguments[0].lower() == "server")
            print_share_info = (arguments[0].lower() == "share")
        else:
            print_server_info = True
            print_share_info = True

        try:
            self.sessionsManager.current_session.info(
                share=print_share_info,
                server=print_server_info
            )
        except SMBConnectionSessionError as e:
            self.logger.error("SMB Error: %s" % e)

    @command_arguments_required
    def command_lbat(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        # Parse wildcards
        files_and_directories = resolve_local_files(arguments)

        for path_to_file in files_and_directories:
            # Read the file
            try:
                if os.path.exists(path=path_to_file):
                    f = open(path_to_file, 'rb')
                    rawcontents = f.read()
                    #
                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]
                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            lexer = Syntax.guess_lexer(path=ntpath.basename(path_to_file), code=filecontent)
                            # Some trickery for the files undetected by the lexer
                            if lexer == "default":
                                if '<?xml' in filecontent:
                                    lexer = "xml"
                                elif '<html>' in filecontent:
                                    lexer = "html"
                            syntax = Syntax(code=filecontent, line_numbers=True, lexer=lexer)
                            if len(files_and_directories) > 1:
                                self.logger.print("\x1b[1;93m[>] %s\x1b[0m" % (path_to_file+' ').ljust(80,'='))
                            Console().print(syntax)
                        else:
                            self.logger.error("[!] Could not detect charset of '%s'." % path_to_file)
                else:
                    self.logger.error("[!] Local file '%s' does not exist." % path_to_file)
            except SMBConnectionSessionError as e:
                self.logger.error("[!] SMB Error: %s" % e)

    @command_arguments_required
    def command_lcat(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        # Parse wildcards
        files_and_directories = resolve_local_files(arguments)

        for path_to_file in files_and_directories:
            # Read the file 
            try:
                if os.path.exists(path=path_to_file):
                    f = open(path_to_file, 'rb')
                    rawcontents = f.read()
                    #
                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]
                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            if len(files_and_directories) > 1:
                                self.logger.print("\x1b[1;93m[>] %s\x1b[0m" % (path_to_file+' ').ljust(80,'='))
                            self.logger.print(filecontent)
                        else:
                            self.logger.error("[!] Could not detect charset of '%s'." % path_to_file)
                else:
                    self.logger.error("[!] Local file '%s' does not exist." % path_to_file)
            except SMBConnectionSessionError as e:
                self.logger.error("[!] SMB Error: %s" % e)

    @command_arguments_required
    def command_lcd(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No
        
        path = arguments[0]

        if os.path.exists(path=path):
            if os.path.isdir(s=path):
                os.chdir(path=path)
            else:
                self.logger.error("Path '%s' is not a directory." % path)
        else:
            self.logger.error("Directory '%s' does not exists." % path)

    @command_arguments_required
    def command_lcp(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) == 2:
            src_path = arguments[0]
            dst_path = arguments[1]
            if os.path.exists(path=src_path):
                try:
                    shutil.copyfile(src=src_path, dst=dst_path)
                except shutil.SameFileError as err:
                    self.logger.error("[!] Error: %s" % err)
            else:
                self.logger.error("[!] File '%s' does not exists." % src_path)
        else:
            self.commandCompleterObject.print_help(command=command)

    def command_lls(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) == 0:
            arguments = ['.']
        else:
            arguments = resolve_local_files(arguments)

        for path in arguments:
            if len(arguments) > 1:
                self.logger.print("%s:" % path)
            # lls <directory>
            if os.path.isdir(path):
                directory_contents = os.listdir(path=path)
                for entryname in sorted(directory_contents):
                    path_to_file = path + os.path.sep + entryname
                    rights_str = unix_permissions(path_to_file)
                    size_str = b_filesize(os.path.getsize(filename=path_to_file))
                    date_str = datetime.datetime.fromtimestamp(os.path.getmtime(filename=path_to_file)).strftime("%Y-%m-%d %H:%M")

                    if os.path.isdir(s=entryname):
                        if self.config.no_colors:
                            self.logger.print("%s %10s  %s  %s%s" % (rights_str, size_str, date_str, entryname, os.path.sep))
                        else:
                            self.logger.print("%s %10s  %s  \x1b[1;96m%s\x1b[0m%s" % (rights_str, size_str, date_str, entryname, os.path.sep))
                    else:
                        if self.config.no_colors:
                            self.logger.print("%s %10s  %s  %s" % (rights_str, size_str, date_str, entryname))
                        else:
                            self.logger.print("%s %10s  %s  \x1b[1m%s\x1b[0m" % (rights_str, size_str, date_str, entryname))
            # lls <file>
            elif os.path.isfile(path):
                rights_str = unix_permissions(path)
                size_str = b_filesize(os.path.getsize(filename=path))
                date_str = datetime.datetime.fromtimestamp(os.path.getmtime(filename=path)).strftime("%Y-%m-%d %H:%M")
                if self.config.no_colors:
                    self.logger.print("%s %10s  %s  %s" % (rights_str, size_str, date_str, os.path.basename(path)))
                else:
                    self.logger.print("%s %10s  %s  \x1b[1m%s\x1b[0m" % (rights_str, size_str, date_str, os.path.basename(path))) 
            
            if len(arguments) > 1:
                self.logger.print()

    @command_arguments_required
    def command_lmkdir(self,arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        for path in arguments:
            if os.path.sep in path:
                path = path.strip(os.path.sep).split(os.path.sep)
            else:
                path = [path]

            # Create each dir in the path
            for depth in range(1, len(path)+1):
                tmp_path = os.path.sep.join(path[:depth])
                if not os.path.exists(tmp_path):
                    os.mkdir(path=tmp_path)

    def command_lpwd(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.logger.print(os.getcwd())

    @command_arguments_required
    def command_lrename(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) == 2:
            os.rename(src=arguments[0], dst=arguments[1])
        else:
            self.commandCompleterObject.print_help(command=command)

    @command_arguments_required
    def command_lrm(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        path = arguments[0]

        if os.path.exists(path):
            if not os.path.isdir(s=path):
                try:
                    os.remove(path=path)
                except Exception as e:
                    self.logger.error("Error removing file '%s' : %s" % path)
            else:
                self.logger.error("Cannot delete '%s'. It is a directory, use 'lrmdir <directory>' instead." % path)
        else:
            self.logger.error("Path '%s' does not exist." % path)

    @command_arguments_required
    def command_lrmdir(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) == 0:
            path = '.'
        else:
            path = arguments[0]

        if os.path.exists(path):
            if os.path.isdir(s=path):
                try:
                    shutil.rmtree(path=path)
                except Exception as e:
                    self.logger.error("Error removing directory '%s' : %s" % path)
            else:
                self.logger.error("Cannot delete '%s'. It is a file, use 'lrm <file>' instead." % path)
        else:
            self.logger.error("Path '%s' does not exist." % path)

    def command_ltree(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        if len(arguments) == 0:
            path = '.'
        else:
            path = arguments[0]

        if len(arguments) == 0:
            local_tree(path='.', config=self.config)
        else:
            local_tree(path=path, config=self.config)

    @active_smb_connection_needed
    @smb_share_is_set
    def command_ls(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        if len(arguments) == 0:
            arguments = ['.']
        else:
            arguments = resolve_remote_files(self.sessionsManager.current_session, arguments)

        for path in arguments:
            if len(arguments) > 1:
                self.logger.print("%s:" % path)

            if self.sessionsManager.current_session.path_isdir(pathFromRoot=path):
                # Read the files
                directory_contents = self.sessionsManager.current_session.list_contents(path=path)
            else:
                entry = self.sessionsManager.current_session.get_entry(path=path)
                if entry is not None:
                    directory_contents = {entry.get_longname(): entry}
                else:
                    directory_contents = {}

            for longname in sorted(directory_contents.keys(), key=lambda x:x.lower()):
                self.logger.print(windows_ls_entry(directory_contents[longname], self.config))

            if len(arguments) > 1:
                self.logger.print()

    @active_smb_connection_needed
    @smb_share_is_set
    def command_acls(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        if len(arguments) == 0:
            arguments = ['.']
        
        smbClient = self.sessionsManager.current_session.smbClient
        sharename = self.sessionsManager.current_session.smb_share
        foldername = self.sessionsManager.current_session.smb_cwd
        tree_id = smbClient.connectTree(sharename)

        for entry in smbClient.listPath(sharename, ntpath.join(foldername, '*')):
            self.logger.print(windows_ls_entry(entry, self.config))
            filename = entry.get_longname()

            if filename in [".",".."]:
                continue
            filename = ntpath.join(foldername, filename)
            try:
                file_id = smbClient.getSMBServer().create(tree_id, filename, READ_CONTROL | FILE_READ_ATTRIBUTES, 0, FILE_DIRECTORY_FILE if entry.is_directory() else FILE_NON_DIRECTORY_FILE, FILE_OPEN, 0)
            except Exception as err:
                self.logger.debug(f"Could not get attributes for file {filename}: {str(err)}")
                continue

            file_info = smbClient.getSMBServer().queryInfo(tree_id, file_id, infoType=SMB2_0_INFO_SECURITY, fileInfoClass=SMB2_SEC_INFO_00, additionalInformation=OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, flags=0)

            self.sessionsManager.current_session.printSecurityDescriptorTable(file_info, filename)

            self.logger.print()

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_mkdir(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        self.sessionsManager.current_session.mkdir(path=arguments[0])

    @command_arguments_required
    def command_module(self, arguments: list[str], command: str):
        module_name = arguments[0]

        if module_name in self.modules.keys():
            module = self.modules[module_name](self.sessionsManager.current_session, self.config, self.logger)
            arguments_string = ' '.join(arguments[1:])
            module.run(arguments_string)
        else:
            self.logger.error("Module '%s' does not exist." % module_name)

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_mount(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        if len(arguments) == 2:
            remote_path = arguments[0]
            if not remote_path.startswith(ntpath.sep):
                remote_path = self.sessionsManager.current_session.smb_cwd + ntpath.sep + remote_path

            local_mount_point = arguments[1]

            self.logger.debug("Trying to mount remote '%s' onto local '%s'" % (remote_path, local_mount_point))

            try:
                self.sessionsManager.current_session.mount(local_mount_point, remote_path)
            except (SMBConnectionSessionError, SMB3SessionError) as e:
                self.sessionsManager.current_session.umount(local_mount_point)
        else:
            self.commandCompleterObject.print_help(command=command)

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_put(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes
        
        is_recursive = False
        while '-r' in arguments:
            is_recursive = True
            arguments.remove('-r')

        # This is the usecase of 'put -r' with no other argument
        if len(arguments) == 0:
            arguments = ['*']

        # Parse wildcards
        files_and_directories = resolve_local_files(arguments)

        # 
        for localpath in files_and_directories:
            try:
                self.logger.print(localpath)
                if is_recursive and os.path.isdir(s=localpath):
                    # Put files recursively
                    self.sessionsManager.current_session.put_file_recursively(localpath=localpath)
                else:
                    # Put this single file
                    self.sessionsManager.current_session.put_file(localpath=localpath)
            except SMBConnectionSessionError as e:
                self.logger.error("[!] SMB Error: %s" % e)

    def command_reconnect(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No

        self.sessionsManager.current_session.ping_smb_session()
        if self.sessionsManager.current_session.connected:
            self.sessionsManager.current_session.close_smb_session()
            self.sessionsManager.current_session.init_smb_session()
        else:
            self.sessionsManager.current_session.init_smb_session()

    def command_reset(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : No
        # SMB share needed             : No
        sys.stdout.write('\x1b[?25h') # Sets the cursor to on
        sys.stdout.write('\x1b[v')  
        sys.stdout.write('\x1b[o') # Reset
        sys.stdout.flush()

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_rm(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        for path_to_file in arguments:
            # Check if the path is absolute
            # Fullpath is required to check if path is a file
            if ntpath.isabs(path_to_file):
                full_path = ntpath.normpath(path_to_file)
            else:
                # Relative path, construct full path
                full_path = ntpath.normpath(ntpath.join(self.sessionsManager.current_session.smb_cwd, path_to_file))
            # Wildcard handling
            if '*' in path_to_file:
                self.sessionsManager.current_session.rm(path=path_to_file)
            # File
            elif self.sessionsManager.current_session.path_exists(path_to_file):
                if self.sessionsManager.current_session.path_isfile(full_path):
                    try:
                        self.sessionsManager.current_session.rm(path=path_to_file)
                    except Exception as e:
                        self.logger.error("Error removing file '%s' : %s" % path_to_file)
                else:
                    self.logger.error("Cannot delete '%s': This is a directory, use 'rmdir <directory>' instead." % path_to_file)
            # File does not exist
            else:
                self.logger.error("Remote file '%s' does not exist." % path_to_file)

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_rmdir(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        for path_to_directory in arguments:
            if self.sessionsManager.current_session.path_exists(path_to_directory):
                if self.sessionsManager.current_session.path_isdir(path_to_directory):
                    try:
                        self.sessionsManager.current_session.rmdir(path=path_to_directory)
                    except Exception as e:
                        self.logger.error("Error removing directory '%s' : %s" % path_to_directory)
                else:
                    self.logger.error("Cannot delete '%s': This is a file, use 'rm <file>' instead." % path_to_directory)
            else:
                self.logger.error("Remote directory '%s' does not exist." % path_to_directory)

    @active_smb_connection_needed
    @smb_share_is_set
    def command_sizeof(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        # Parse the arguments to get the path(s)
        if len(arguments) == 0:
            paths = [self.sessionsManager.current_session.smb_cwd or '']
        else:
            paths = arguments  # Assuming arguments is a list of paths

        total_size = 0
        for path in paths:
            # Normalize and parse the path
            path = path.replace('/', ntpath.sep)
            path = ntpath.normpath(path)
            path = path.strip(ntpath.sep)

            # Handle relative and absolute paths
            if not ntpath.isabs(path):
                path = ntpath.normpath(ntpath.join(self.sessionsManager.current_session.smb_cwd or '', path))
            else:
                path = path.lstrip(ntpath.sep)
                path = ntpath.normpath(path)

            try:
                # Initialize the generator
                generator = smb_entry_iterator(
                    smb_client=self.sessionsManager.current_session.smbClient,
                    smb_share=self.sessionsManager.current_session.smb_share,
                    start_paths=[path],
                    exclusion_rules=[],
                    max_depth=None
                )

                path_size = 0
                
                LINE_CLEAR = '\x1b[2K'

                # Prepare the path display
                if self.config.no_colors:
                    path_display = path
                else:
                    path_display = f"\x1b[1;96m{path}\x1b[0m"

                size_str = ""
                for entry, fullpath, depth, is_last_entry in generator:
                    if not entry.is_directory():
                        path_size += entry.get_filesize()
                        # Update the size display each time path_size is incremented
                        size_str = b_filesize(path_size)
                        output_line = f"\r{size_str}\t{path_display}"
                        # Clear the line after the cursor
                        print(output_line, end='\r')

                # After processing all entries, format and print the result for the current path
                print(end=LINE_CLEAR)
                print(f"{size_str}\t{path_display}")
                total_size += path_size

            except SMBConnectionSessionError as e:
                self.logger.error(f"Failed to access '{path}': {e}")
            except (BrokenPipeError, KeyboardInterrupt):
                self.logger.error("Interrupted.")
                return
            except Exception as e:
                self.logger.error(f"Error while processing '{path}': {e}")

        # If multiple paths, print the total size
        if len(paths) > 1:
            self.logger.print("──────────────────────")
            self.logger.print(f"Total size: {b_filesize(total_size)}")

    @active_smb_connection_needed
    def command_shares(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : No

        test_write = False
        do_check_rights = False
        if len(arguments) != 0:
            if arguments[0] == "rights":
                do_check_rights = True
                test_write = False

        if do_check_rights:
            self.logger.print("WARNING: Checking WRITE access to shares in offensive tools implies creating a folder and trying to delete it.")
            self.logger.print("| If you have CREATE_CHILD rights but no DELETE_CHILD rights, the folder cannot be deleted and will remain on the target.")
            self.logger.print("| Do you want to continue? [N/y] ", end='')
            user_response = input()
            self.logger.write_to_logfile(user_response)
            while user_response.lower().strip() not in ['y', 'n']:
                self.logger.print("| Invalid response, Do you want to continue? [N/y] ", end='')
                user_response = input()
                self.logger.write_to_logfile(user_response)
            if user_response.lower().strip() == 'y':
                test_write = True

        shares = self.sessionsManager.current_session.list_shares()
        if len(shares.keys()) != 0:
            table = Table(title=None)
            table.add_column("Share")
            table.add_column("Visibility")
            table.add_column("Type")
            table.add_column("Description", justify="left")
            if do_check_rights:
                table.add_column("Rights")

            security_descriptor = list(shares.values())[0].get("security_descriptor")
            if security_descriptor is not None:
                table.add_column("Security Descriptor")

            for sharename in sorted(shares.keys()):
                types = ', '.join([s.replace("STYPE_","") for s in shares[sharename]["type"]])

                is_hidden = bool(sharename.endswith('$'))
                if is_hidden:
                    str_hidden = "[bold bright_blue]Hidden[/bold bright_blue]"
                    str_sharename = "[bold bright_blue]" + shares[sharename]["name"] + "[/bold bright_blue]"
                    str_types = "[bold bright_blue]" + types + "[/bold bright_blue]"
                    str_comment = "[bold bright_blue]" + shares[sharename]["comment"] + "[/bold bright_blue]"
                else:
                    str_hidden = "[bold bright_yellow]Visible[/bold bright_yellow]"
                    str_sharename = "[bold bright_yellow]" + shares[sharename]["name"] + "[/bold bright_yellow]"
                    str_types = "[bold bright_yellow]" + types + "[/bold bright_yellow]"
                    str_comment = "[bold bright_yellow]" + shares[sharename]["comment"] + "[/bold bright_yellow]"

                if do_check_rights:
                    try:
                        access_rights = self.sessionsManager.current_session.test_rights(sharename=shares[sharename]["name"], test_write=test_write)
                        str_access_rights = "[bold yellow]NO ACCESS[/bold yellow]"
                        if access_rights["readable"] and access_rights["writable"]:
                            str_access_rights = "[bold green]READ[/bold green], [bold red]WRITE[/bold red]"
                        elif access_rights["readable"]:
                            str_access_rights = "[bold green]READ[/bold green]"
                        elif access_rights["writable"]:
                            # Without READ?? This should not happen IMHO
                            str_access_rights = "[bold red]WRITE[/bold red]"
                        else:
                            str_access_rights = "[bold yellow]NO ACCESS[/bold yellow]"
                    except:
                        str_access_rights = ""

                if security_descriptor is not None:
                    sd_table = self.sessionsManager.current_session.securityDescriptorTable(b''.join(shares[sharename].get("security_descriptor")), "sharename", prefix="", table_colors=True)

                if do_check_rights:
                    if security_descriptor is not None:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment, str_access_rights, sd_table)
                    else:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment, str_access_rights)
                else:
                    if security_descriptor is not None:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment, sd_table)
                    else:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment)

            Console().print(table)
        else:
            self.logger.error("No share served on '%s'" % self.sessionsManager.current_session.host)

    @active_smb_connection_needed
    @smb_share_is_set
    def command_tree(self, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        if len(arguments) == 0:
            self.sessionsManager.current_session.tree(path='.')
        else:
            self.sessionsManager.current_session.tree(path=arguments[0])

    @command_arguments_required
    @active_smb_connection_needed
    @smb_share_is_set
    def command_umount(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        local_mount_point = arguments[0]

        self.logger.debug("Trying to unmount local mount point '%s'" % (local_mount_point))
        
        self.sessionsManager.current_session.umount(local_mount_point)
        
    @command_arguments_required
    @active_smb_connection_needed
    def command_use(self, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : No

        sharename = arguments[0]

        # Reload the list of shares
        shares = self.sessionsManager.current_session.list_shares()
        shares = [s.lower() for s in shares.keys()]

        if sharename.lower() in shares:
            self.sessionsManager.current_session.set_share(sharename)
        else:
            self.logger.error("No share named '%s' on '%s'" % (sharename, self.sessionsManager.current_session.host))

    # Private functions =======================================================

    def __load_modules(self):
        """
        Dynamically loads all Python modules from the 'modules' directory and stores them in the 'modules' dictionary.
        Each module is expected to be a Python file that contains a class with the same name as the file (minus the .py extension).
        The class must have at least two attributes: 'name' and 'description'.
        
        This method clears any previously loaded modules, constructs the path to the modules directory, and iterates over
        each file in that directory. If the file is a Python file (ends with .py and is not '__init__.py'), it attempts to
        import the module and access the class within it to add to the 'modules' dictionary.
        
        If debug mode is enabled in the configuration, it prints debug information about the loading process and the loaded modules.
        """

        self.modules.clear()

        modules_dir = os.path.normpath(os.path.dirname(__file__) + os.path.sep + ".." + os.path.sep + "modules")
        self.logger.debug("[>] Loading modules from %s ..." % modules_dir)
        sys.path.extend([modules_dir])

        for file in os.listdir(modules_dir):
            filepath = os.path.normpath(modules_dir + os.path.sep + file)
            if file.endswith('.py'):
                if os.path.isfile(filepath) and file not in ["__init__.py"]:
                    try:
                        module_file = import_module('smbclientng.modules.%s' % (file[:-3]))
                        module = module_file.__getattribute__(file[:-3])
                        self.modules[module.name.lower()] = module
                    except AttributeError as err:
                        pass
                    except ImportError as err:
                        self.logger.debug("[!] Could not load module '%s': %s" % ((file[:-3]), err))

        if self.config.debug:
            if len(self.modules.keys()) == 0:
                self.logger.debug("[>] Loaded 0 modules.")
            elif len(self.modules.keys()) == 1:
                self.logger.debug("[>] Loaded 1 module:")
            else:
                self.logger.debug("[>] Loaded %d modules:" % len(self.modules.keys()))
            for modulename in sorted(self.modules.keys()):
                self.logger.debug("  | %s : \"%s\" (%s)" % (self.modules[modulename].name, self.modules[modulename].description, self.modules[modulename]))

        if self.commandCompleterObject is not None:
            self.commandCompleterObject.commands["module"]["subcommands"] = list(self.modules.keys())

    def __prompt(self):
        """
        Prints the command prompt for the interactive shell.

        This method constructs and returns the command prompt string based on the current state of the SMB session.
        The prompt indicates the connection status with a visual symbol and displays the current working directory
        or the SMB share path. The prompt appearance changes based on whether colors are enabled in the configuration.

        Returns:
            str: The formatted command prompt string.
        """

        # A session exists
        if self.sessionsManager.current_session is not None:
            # Check if the session is still active
            self.sessionsManager.current_session.ping_smb_session()
            if self.sessionsManager.current_session.connected:
                if self.config.no_colors:
                    connected_dot = "[v]"
                else:
                    connected_dot = "\x1b[1;92m■\x1b[0m"
            else:
                if self.config.no_colors:
                    connected_dot = "[x]"
                else:
                    connected_dot = "\x1b[1;91m■\x1b[0m"
            
            # Session ID if 
            session_prompt = ""
            if len(self.sessionsManager.sessions.keys()) >= 2:
                session_prompt = "[#%d]" % self.sessionsManager.current_session_id

            # No share set yet
            if self.sessionsManager.current_session.smb_share is None:
                str_path = "\\\\%s\\" % self.sessionsManager.current_session.host
            # A share is set
            else:
                if len(self.sessionsManager.current_session.smb_cwd) == 0:
                    current_path = ""
                else:
                    current_path = self.sessionsManager.current_session.smb_cwd.strip(ntpath.sep) + ntpath.sep
                
                str_path = "\\\\%s\\%s\\%s" % (self.sessionsManager.current_session.host, self.sessionsManager.current_session.smb_share, current_path)
        # No active session
        else:
            connected_dot = ""
            session_prompt = ""
            str_path = "No active session"

        # Build final prompt string
        if self.config.no_colors:
            str_prompt = "%s%s[%s]> " % (connected_dot, session_prompt, str_path)
        else:
            str_prompt = "%s%s[\x1b[1;94m%s\x1b[0m]> " % (connected_dot, session_prompt, str_path)

        return str_prompt
