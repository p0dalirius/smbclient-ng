#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : smbclient-ng.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 may 2024

import argparse
import datetime
import ntpath
import os
import readline
import re
import stat
import sys
import shutil
import traceback
import impacket
from impacket.smbconnection import SMBConnection as impacketSMBConnection
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn
from rich.console import Console
from rich.table import Table


VERSION = "2.1.1"


# Extracted from p0dalirius/sectools library
# Src: https://github.com/p0dalirius/sectools/blob/7bb3f5cb7815ad4d4845713c8739e2e2b0ea4e75/sectools/windows/crypto.py#L11-L24
def parse_lm_nt_hashes(lm_nt_hashes_string):
    lm_hash_value, nt_hash_value = "", ""
    if lm_nt_hashes_string is not None:
        matched = re.match("([0-9a-f]{32})?(:)?([0-9a-f]{32})?", lm_nt_hashes_string.strip().lower())
        m_lm_hash, m_sep, m_nt_hash = matched.groups()
        if m_lm_hash is None and m_sep is None and m_nt_hash is None:
            lm_hash_value, nt_hash_value = "", ""
        elif m_lm_hash is None and m_nt_hash is not None:
            lm_hash_value = "aad3b435b51404eeaad3b435b51404ee"
            nt_hash_value = m_nt_hash
        elif m_lm_hash is not None and m_nt_hash is None:
            lm_hash_value = m_lm_hash
            nt_hash_value = "31d6cfe0d16ae931b73c59d7e0c089c0"
    return lm_hash_value, nt_hash_value


def b_filesize(l):
    """
    Convert a file size from bytes to a more readable format using the largest appropriate unit.

    This function takes an integer representing a file size in bytes and converts it to a human-readable
    string using the largest appropriate unit from bytes (B) to petabytes (PB). The result is rounded to
    two decimal places.

    Args:
        l (int): The file size in bytes.

    Returns:
        str: A string representing the file size in a more readable format, including the appropriate unit.
    """
    units = ['B','kB','MB','GB','TB','PB']
    for k in range(len(units)):
        if l < (1024**(k+1)):
            break
    return "%4.2f %s" % (round(l/(1024**(k)),2), units[k])


def unix_permissions(entryname):
    """
    Generate a string representing the Unix-style permissions for a given file or directory.

    This function uses the os.lstat() method to retrieve the status of the specified file or directory,
    then constructs a string that represents the Unix-style permissions based on the mode of the file.

    Args:
        entryname (str): The path to the file or directory for which permissions are being determined.

    Returns:
        str: A string of length 10 representing the Unix-style permissions (e.g., '-rwxr-xr--').
             The first character is either 'd' (directory), '-' (not a directory), followed by
             three groups of 'r', 'w', 'x' (read, write, execute permissions) for owner, group,
             and others respectively.
    """
    mode = os.lstat(entryname).st_mode
    permissions = []

    permissions.append('d' if stat.S_ISDIR(mode) else '-')

    permissions.append('r' if mode & stat.S_IRUSR else '-')
    permissions.append('w' if mode & stat.S_IWUSR else '-')
    permissions.append('x' if mode & stat.S_IXUSR else '-')

    permissions.append('r' if mode & stat.S_IRGRP else '-')
    permissions.append('w' if mode & stat.S_IWGRP else '-')
    permissions.append('x' if mode & stat.S_IXGRP else '-')

    permissions.append('r' if mode & stat.S_IROTH else '-')
    permissions.append('w' if mode & stat.S_IWOTH else '-')
    permissions.append('x' if mode & stat.S_IXOTH else '-')

    return ''.join(permissions)


class CommandCompleter(object):
    """
    A class to handle command completion for the smbclient-ng shell.

    This class provides a command completion feature that suggests possible command names based on the current input.
    It uses a dictionary to store commands and their descriptions, which helps in providing hints during the command line
    interaction in the smbclient-ng shell.

    Attributes:
        smbSession (SMBSession): An instance of SMBSession which maintains the current SMB session.
        commands (dict): A dictionary containing command names as keys and their descriptions and subcommands as values.

    Methods:
        __init__(self, smbSession): Initializes the CommandCompleter with an SMBSession.
    """
    def __init__(self, smbSession):
        self.smbSession = smbSession
        self.commands = {
            "cd": {
                "description": ["Change the current working directory.", "Syntax: 'cd <directory>'"], 
                "subcommands": []
            },
            "close": {
                "description": ["Closes the SMB connection to the remote machine.", "Syntax: 'close'"], 
                "subcommands": []
            },
            "dir": {
                "description": ["List the contents of the current working directory.", "Syntax: 'dir'"], 
                "subcommands": []
            },
            "exit": {
                "description": ["Exits the smbclient-ng script.", "Syntax: 'exit'"], 
                "subcommands": []
            },
            "get": {
                "description": ["Get a remote file.", "Syntax: 'get [-r] <directory or file>'"], 
                "subcommands": []
            },
            "help": {
                "description": ["Displays this help message.", "Syntax: 'help'"], 
                "subcommands": ["format"]
            },
            "info": {
                "description": ["Get information about the server and or the share.", "Syntax: 'info [server|share]'"], 
                "subcommands": ["server", "share"]
            },
            "lcd": {
                "description": ["Changes the current local directory.", "Syntax: 'lcd <directory>'"], 
                "subcommands": []
            },
            "lls": {
                "description": ["Lists the contents of the current local directory.", "Syntax: 'lls'"], 
                "subcommands": []
            },
            "lmkdir": {
                "description": ["Creates a new local directory.", "Syntax: 'lmkdir <directory>'"], 
                "subcommands": []
            },
            "lpwd": {
                "description": ["Shows the current local directory.", "Syntax: 'lpwd'"], 
                "subcommands": []
            },
            "lrm": {
                "description": ["Removes a local file.", "Syntax: 'lrm <file>'"], 
                "subcommands": []
            },
            "lrmdir": {
                "description": ["Removes a local directory.", "Syntax: 'lrmdir <directory>'"], 
                "subcommands": []
            },
            "ls": {
                "description": ["List the contents of the current remote working directory.", "Syntax: 'ls'"], 
                "subcommands": []
            },
            "mkdir": {
                "description": ["Creates a new remote directory.", "Syntax: 'mkdir <directory>'"], 
                "subcommands": []
            },
            "put": {
                "description": ["Put a local file or directory in a remote directory.", "Syntax: 'put [-r] <directory or file>'"], 
                "subcommands": []
            },
            "reconnect": {
                "description": ["Reconnect to the remote machine (useful if connection timed out).", "Syntax: 'reconnect'"], 
                "subcommands": []
            },
            "rmdir": {
                "description": ["Removes a remote directory.", "Syntax: 'rmdir <directory>'"], 
                "subcommands": []
            },
            "rm": {
                "description": ["Removes a remote file.", "Syntax: 'rm <file>'"], 
                "subcommands": []
            },
            "shares": {
                "description": ["Lists the SMB shares served by the remote machine.", "Syntax: 'shares'"], 
                "subcommands": []
            },
            "use": {
                "description": ["Use a SMB share.", "Syntax: use <sharename>"], 
                "subcommands": []
            },
            "tree": {
                "description": ["Displays a tree view of the nested subfolders.", "Syntax: tree [directory]"], 
                "subcommands": []
            },
        }
        
        self.commands["help"]["subcommands"] = ["format"] + list(self.commands.keys())
        self.commands["help"]["subcommands"].remove("help")

    def complete(self, text, state):
        """
        Function to handle command completion in the LDAP console.

        This function completes the user"s input based on the available options for commands in the LDAP console.

        Args:
            text (str): The current text input by the user.
            state (int): The current state of completion.

        Returns:
            str: The next completion suggestion based on the user"s input state.
        """
        if state == 0:
            
            # No text typed yet, need the list of commands available
            if len(text) == 0:
                self.matches = [s for s in self.commands.keys()]

            elif len(text) != 0:
                # This is for the main command
                if text.count(" ") == 0:
                    self.matches = [s for s in self.commands.keys() if s and s.startswith(text)]
                
                # This is for subcommands
                elif text.count(" ") >= 1:
                    command, remainder = text.split(" ", 1)
                    if command in self.commands.keys():
                        if command == "use":
                            # Choose SMB Share to connect to
                            self.matches = [command + " " + s for s in self.smbSession.list_shares().keys() if s and s.startswith(remainder)]
                        elif command == "cd":
                            # Choose directory
                            directory_contents = list(self.smbSession.list_contents().keys())
                            self.matches = [command + " " + s for s in directory_contents if s and s.startswith(remainder)]
                        else:
                            # Generic case for subcommands
                            self.matches = [command + " " + s for s in self.commands[command]["subcommands"] if s and s.startswith(remainder)]
                    else:
                        # Unknown subcommand, skipping autocomplete
                        pass
                else:
                    self.matches = []
            else:
                self.matches = self.commands.keys()[:]

        try:
            return self.matches[state] + " "
        except IndexError:
            return None

    def print_help(self, command=None):
        if command != None:
            if command not in list(self.commands.keys())+["format"]:
                command = None

        if command != None:
            if command == "format":
                self.print_help_format()
            else:
                print("│")
                command_str = command + " \x1b[90m" + "─"* (15 - len(command)) + "\x1b[0m"
                if len(self.commands[command]["description"]) == 0:
                    print("│ ■ %s\x1b[90m┤\x1b[0m  " % command_str)
                elif len(self.commands[command]["description"]) == 1:
                    print("│ ■ %s\x1b[90m┤\x1b[0m %s " % (command_str, self.commands[command]["description"][0]))
                else:
                    print("│ ■ %s\x1b[90m┤\x1b[0m %s " % (command_str, self.commands[command]["description"][0]))
                    for line in self.commands[command]["description"][1:]:
                        print("│ %s\x1b[90m│\x1b[0m %s " % (" "*(15+3), line))
                print("│")

        else:
            print("│")
            commands = sorted(self.commands.keys())
            for command in commands:
                command_str = command + " \x1b[90m" + "─"* (15 - len(command)) + "\x1b[0m"
                if len(self.commands[command]["description"]) == 0:
                    print("│ ■ %s\x1b[90m┤\x1b[0m  " % command_str)
                elif len(self.commands[command]["description"]) == 1:
                    print("│ ■ %s\x1b[90m┤\x1b[0m %s " % (command_str, self.commands[command]["description"][0]))
                else:
                    print("│ ■ %s\x1b[90m┤\x1b[0m %s " % (command_str, self.commands[command]["description"][0]))
                    for line in self.commands[command]["description"][1:]:
                        print("│ %s\x1b[90m│\x1b[0m %s " % (" "*(15+3), line))
                print("│")

    def print_help_format(self):
        print("File attributes format:\n")
        print("\x1b[1mdachnrst\x1b[0m")
        print("\x1b[90m│││││││└──>\x1b[0m Temporary")
        print("\x1b[90m││││││└───>\x1b[0m System")
        print("\x1b[90m│││││└────>\x1b[0m Read-Only")
        print("\x1b[90m││││└─────>\x1b[0m Normal")
        print("\x1b[90m│││└──────>\x1b[0m Hidden")
        print("\x1b[90m││└───────>\x1b[0m Compressed")
        print("\x1b[90m│└────────>\x1b[0m Archived")
        print("\x1b[90m└─────────>\x1b[0m Directory")


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

        #
        self.smb_share = None
        self.smb_path = ""

        #
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
                
                # Skip
                if command == "":
                    pass

                # Exit the command line
                elif command == "exit":
                    running = False

                # Display help
                elif command == "help":
                    if len(arguments) != 0:
                        self.commandCompleterObject.print_help(command=arguments[0])
                    else:
                        self.commandCompleterObject.print_help(command=None)

                elif command in self.commandCompleterObject.commands.keys():
                    self.process_command(command=command, arguments=arguments)

                # Fallback to unknown command
                else:
                    print("Unknown command. Type \"help\" for help.")

            except KeyboardInterrupt as e:
                print()
                running = False

            except EOFError as e:
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
        
        # Change directory to a share
        elif command == "cd":
            if self.smb_share is not None:
                if len(arguments) != 0:
                    path = ' '.join(arguments).replace('/',r'\\')
                    path = path + '\\'
                    path = re.sub(r'\\+', r'\\', path)

                    if not path.startswith('\\'):
                        # Relative path
                        path = self.smb_path + path
                    
                    path = ntpath.normpath(path=path) + '\\'
                    if path == '.\\':
                        path = ""

                    try:
                        self.smbSession.list_contents(shareName=self.smb_share, path=path)
                        self.smb_path = path
                    except impacket.smbconnection.SessionError as e:
                        print("[!] SMB Error: %s" % e)
                else:
                    print("[!] Syntax: 'cd <path>'")
            else:
                print("[!] You must open a share first, try the 'use <share>' command.")

        # Closes the current SMB session
        elif command == "close":
            self.smbSession.ping_smb_session()
            if self.smbSession.connected:
                self.smbSession.close_smb_session()

        # Get a file
        elif command == "get":
            if len(arguments) != 0:
                self.smbSession.ping_smb_session()
                if self.smbSession.connected:
                    if self.smb_share is not None:
                        # Get files recursively
                        if arguments[0] == "-r":
                            path = ' '.join(arguments[1:]).replace('/',r'\\')
                            try:
                                self.smbSession.get_file_recursively(path=path)
                            except impacket.smbconnection.SessionError as e:
                                print("[!] SMB Error: %s" % e)

                        # Get a single file
                        else:
                            path = ' '.join(arguments).replace('/',r'\\')
                            try:
                                self.smbSession.get_file(path=path)
                            except impacket.smbconnection.SessionError as e:
                                print("[!] SMB Error: %s" % e)
                    else:
                        print("[!] You must open a share first, try the 'use <share>' command.")
                else:
                    print("[!] SMB Session is disconnected.")
            else:
                self.commandCompleterObject.print_help(command=command)
            
        # SMB server info
        elif command == "info":
            self.smbSession.ping_smb_session()
            if self.smbSession.connected:
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
            else:
                print("[!] SMB Session is disconnected.")

        # Changes the current local directory
        elif command == "lcd":
            if len(arguments) != 0:
                path = ' '.join(arguments)
                if os.path.exists(path=path):
                    if os.path.isdir(s=path):
                        os.chdir(path=path)
                    else:
                        print("[!] Path '%s' is not a directory." % path)
                else:
                    print("[!] Directory '%s' does not exists." % path)
            else:
                self.commandCompleterObject.print_help(command=command)

        # Lists the contents of the current local directory
        elif command == "lls":
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

        # Creates a new local directory
        elif command == "lmkdir":
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

        # Removes a local file
        elif command == "lrm":
            path = ' '.join(arguments)
            if os.path.exists(path):
                if not os.path.isdir(s=path):
                    try:
                        os.remove(path=path)
                    except Exception as e:
                        print("[!] Error removing file '%s' : %s" % path)
                else:
                    print("[!] Cannot delete '%s': This is a directory, use 'lrmdir <directory>' instead." % path)

        # Removes a local directory
        elif command == "lrmdir":
            path = ' '.join(arguments)
            if os.path.exists(path):
                if os.path.isdir(s=path):
                    try:
                        shutil.rmtree(path=path)
                    except Exception as e:
                        print("[!] Error removing directory '%s' : %s" % path)
                else:
                    print("[!] Cannot delete '%s': This is a file, use 'lrm <file>' instead." % path)

        # Shows the current local directory
        elif command == "lpwd":
            # print("Current local working directory:")
            print(os.getcwd())

        # Change directory to a share
        elif command in ["ls", "dir"]:
            self.smbSession.ping_smb_session()
            if self.smbSession.connected:
                if self.smb_share is not None:
                    # Read the files
                    directory_contents = self.smbSession.list_contents(
                        shareName=self.smb_share, 
                        path=self.smb_path
                    )

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
                else:
                    print("[!] You must open a share first, try the 'use <share>' command.")
            else:
                print("[!] SMB Session is disconnected.")

        # Creates a new remote directory
        elif command == "mkdir":
            if len(arguments) != 0:
                self.smbSession.ping_smb_session()
                if self.smbSession.connected:
                    path = ' '.join(arguments)
                    self.smbSession.mkdir(path=path)
                else:
                    print("[!] SMB Session is disconnected.")
            else:
                self.commandCompleterObject.print_help(command=command)
            
        # Put a file
        elif command == "put":
            if len(arguments) != 0:
                self.smbSession.ping_smb_session()
                if self.smbSession.connected:
                    if self.smb_share is not None:
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
                    else:
                        print("[!] You must open a share first, try the 'use <share>' command.")
                else:
                    print("[!] SMB Session is disconnected.")
            else:
                self.commandCompleterObject.print_help(command=command)
                
        # Reconnects the current SMB session
        elif command in ["reconnect", "connect"]:
            self.smbSession.ping_smb_session()
            if self.smbSession.connected:
                self.smbSession.close()
                self.smbSession.init_smb_session()
            else:
                self.smbSession.init_smb_session()

        # Removes a remote file
        elif command == "rm":
            if len(arguments) != 0:
                self.smbSession.ping_smb_session()
                if self.smbSession.connected:
                    path = ' '.join(arguments)
                    if self.smbSession.path_exists(path):
                        if self.smbSession.path_isfile(path):
                            try:
                                pass
                            except Exception as e:
                                print("[!] Error removing file '%s' : %s" % path)
                        else:
                            print("[!] Cannot delete '%s': This is a directory, use 'rmdir <directory>' instead." % path)
                    else:
                        print("[!] Remote file '%s' does not exist." % path)
                else:
                    print("[!] SMB Session is disconnected.")
            else:
                self.commandCompleterObject.print_help(command=command)
            
        # Removes a remote directory
        elif command == "rmdir":
            if len(arguments) != 0:
                self.smbSession.ping_smb_session()
                if self.smbSession.connected:
                    path = ' '.join(arguments)
                    if self.smbSession.path_exists(path):
                        if self.smbSession.path_isdir(path):
                            try:
                                pass
                            except Exception as e:
                                print("[!] Error removing directory '%s' : %s" % path)
                        else:
                            print("[!] Cannot delete '%s': This is a file, use 'rm <file>' instead." % path)
                    else:
                        print("[!] Remote directory '%s' does not exist." % path)
                else:
                    print("[!] SMB Session is disconnected.")
            else:
                self.commandCompleterObject.print_help(command=command)
            
        # List shares
        elif command == "shares":
            self.smbSession.ping_smb_session()
            if self.smbSession.connected:
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
            else:
                print("[!] SMB Session is disconnected.")

        # Use a share
        elif command == "tree":
            self.smbSession.ping_smb_session()
            if self.smbSession.connected:
                if len(arguments) == 0:
                    self.smbSession.tree(path='.')
                else:
                    self.smbSession.tree(path=' '.join(arguments))
            else:
                print("[!] SMB Session is disconnected.")

        # Use a share
        elif command == "use":
            if len(arguments) != 0:
                self.smbSession.ping_smb_session()
                if self.smbSession.connected:
                    sharename = ' '.join(arguments)
                    # Reload the list of shares
                    self.smbSession.list_shares()
                    if sharename in self.smbSession.shares.keys():
                        self.smb_share = sharename
                        self.smbSession.smb_share = sharename
                    else:
                        print("[!] No share named '%s' on '%s'" % (sharename, self.smbSession.address))
                else:
                    print("[!] SMB Session is disconnected.")
            else:
                self.commandCompleterObject.print_help(command=command)


    def __prompt(self):
        self.smbSession.ping_smb_session()
        if self.smbSession.connected:
            connected_dot = "\x1b[1;92m⏺ \x1b[0m"
        else:
            connected_dot = "\x1b[1;91m⏺ \x1b[0m"
        if self.smb_share is None:
            str_prompt = "%s[\x1b[1;94m\\\\%s\\\x1b[0m]> " % (connected_dot, self.smbSession.address)
        else:
            str_path = "\\\\%s\\%s\\%s" % (self.smbSession.address, self.smb_share, self.smb_path)
            str_prompt = "%s[\x1b[1;94m%s\x1b[0m]> " % (connected_dot, str_path)
        return str_prompt


def STYPE_MASK(stype_value):
    """
    Extracts the share type flags from a given share type value.

    This function uses bitwise operations to determine which share type flags are set in the provided `stype_value`.
    It checks against known share type flags and returns a list of the flags that are set.

    Parameters:
        stype_value (int): The share type value to analyze, typically obtained from SMB share properties.

    Returns:
        list: A list of strings, where each string represents a share type flag that is set in the input value.
    """

    known_flags = {
        ## One of the following values may be specified. You can isolate these values by using the STYPE_MASK value.
        # Disk drive.
        "STYPE_DISKTREE": 0x0,

        # Print queue.
        "STYPE_PRINTQ": 0x1,

        # Communication device.
        "STYPE_DEVICE": 0x2,

        # Interprocess communication (IPC).
        "STYPE_IPC": 0x3,

        ## In addition, one or both of the following values may be specified.
        # Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$).
        # Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see Network Share Functions.
        "STYPE_SPECIAL": 0x80000000,

        # A temporary share.
        "STYPE_TEMPORARY": 0x40000000
    }
    flags = []
    if (stype_value & 0b11) == known_flags["STYPE_DISKTREE"]:
        flags.append("STYPE_DISKTREE")
    elif (stype_value & 0b11) == known_flags["STYPE_PRINTQ"]:
        flags.append("STYPE_PRINTQ")
    elif (stype_value & 0b11) == known_flags["STYPE_DEVICE"]:
        flags.append("STYPE_DEVICE")
    elif (stype_value & 0b11) == known_flags["STYPE_IPC"]:
        flags.append("STYPE_IPC")
    if (stype_value & known_flags["STYPE_SPECIAL"]) == known_flags["STYPE_SPECIAL"]:
        flags.append("STYPE_SPECIAL")
    if (stype_value & known_flags["STYPE_TEMPORARY"]) == known_flags["STYPE_TEMPORARY"]:
        flags.append("STYPE_TEMPORARY")
    return flags


class LocalFileIO(object):
    """
    Class LocalFileIO is designed to handle local file input/output operations within the smbclient-ng tool.
    It provides functionalities to open, read, write, and manage progress of file operations based on the expected size of the file.

    Attributes:
        mode (str): The mode in which the file should be opened (e.g., 'rb', 'wb').
        path (str): The path to the file that needs to be handled.
        expected_size (int, optional): The expected size of the file in bytes. This is used to display progress.
        debug (bool): Flag to enable debug mode which provides additional output during operations.

    Methods:
        __init__(self, mode, path=None, expected_size=None, debug=False): Initializes the LocalFileIO instance.
        write(self, data): Writes data to the file and updates the progress bar if expected size is provided.
        read(self, size): Reads data from the file up to the specified size and updates the progress bar if expected size is provided.
    """

    def __init__(self, mode, path=None, expected_size=None, debug=False):
        super(LocalFileIO, self).__init__()

        self.mode = mode
        self.path = path.replace('\\', '/')
        self.dir = None
        self.debug = False
        self.expected_size = expected_size

        # Write to local (read remote)
        if self.mode in ["wb"]:
            self.dir = './' + os.path.dirname(self.path)

            if not os.path.exists(self.dir):
                if self.debug:
                    print("[debug] Creating local directory '%s'" % self.dir)
                os.makedirs(self.dir)

            if self.debug:
                print("[debug] Openning local '%s' with mode '%s'" % (self.path, self.mode))

            self.fd = open(self.path, self.mode)

        # Write to remote (read local)
        elif self.mode in ["rb"]:
            if '\\' in self.path:
                self.dir = os.path.dirname(self.path)

            if self.debug:
                print("[debug] Openning local '%s' with mode '%s'" % (self.path, self.mode))

            self.fd = open(self.path, self.mode)

            if self.expected_size is None:
                self.expected_size = os.path.getsize(filename=self.path)

        # Create progress bar
        if self.expected_size is not None:
            self.__progress = Progress(
                TextColumn("[bold blue]{task.description}", justify="right"),
                BarColumn(bar_width=None),
                "[progress.percentage]{task.percentage:>3.1f}%",
                "•",
                DownloadColumn(),
                "•",
                TransferSpeedColumn(),
                "•",
                TimeRemainingColumn(),
            )
            self.__progress.start()
            self.__task = self.__progress.add_task(
                description="'%s'" % os.path.basename(self.path),
                start=True,
                total=self.expected_size,
                visible=True
            )

    def write(self, data):
        if self.expected_size is not None:
            self.__progress.update(self.__task, advance=len(data))
        return self.fd.write(data)
    
    def read(self, size):
        read_data = self.fd.read(size)
        if self.expected_size is not None:
            self.__progress.update(self.__task, advance=len(read_data))
        return read_data

    def close(self, remove=False):
        self.fd.close()

        if remove:
            os.remove(path=self.path)

        if self.expected_size is not None:
            self.__progress.stop()

        del self

    def set_error(self, message):
        self.__progress.tasks[0].description = message
        self.__progress.columns = [
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            "•",
            DownloadColumn(),
        ]
        self.__progress.update(self.__task, advance=0)


class SMBSession(object):
    """
    Class SMBSession is designed to handle the session management for SMB (Server Message Block) protocol connections.
    It provides functionalities to connect to an SMB server, authenticate using either NTLM or Kerberos, and manage SMB shares.

    Attributes:
        address (str): The IP address or hostname of the SMB server.
        domain (str): The domain name for SMB server authentication.
        username (str): The username for SMB server authentication.
        password (str): The password for SMB server authentication.
        lmhash (str): The LM hash of the user's password, if available.
        nthash (str): The NT hash of the user's password, if available.
        use_kerberos (bool): A flag to determine whether to use Kerberos for authentication.
        kdcHost (str): The Key Distribution Center (KDC) host for Kerberos authentication.
        debug (bool): A flag to enable debug output.
        smbClient (object): The SMB client object used for the connection.
        connected (bool): A flag to check the status of the connection.
        smb_share (str): The current SMB share in use.
        smb_path (str): The current path within the SMB share.

    Methods:
        __init__(address, domain, username, password, lmhash, nthash, use_kerberos=False, kdcHost=None, debug=False):
            Initializes the SMBSession with the specified parameters.
        init_smb_session():
            Initializes the SMB session by connecting to the server and authenticating using the specified method.
    """

    def __init__(self, address, domain, username, password, lmhash, nthash, use_kerberos=False, kdcHost=None, debug=False):
        super(SMBSession, self).__init__()

        self.debug = debug

        # Target server
        self.address = address

        # Credentials
        self.domain = domain
        self.username = username
        self.password = password 
        self.lmhash = lmhash
        self.nthash = nthash
        self.use_kerberos = use_kerberos
        self.kdcHost = kdcHost

        self.smbClient = None
        self.connected = False

        self.smb_share = None
        self.smb_path = ""

    def close_smb_session(self):
        print("[>] Closing the current SMB connection ...")
        self.smbClient.close()

    def get_file(self, path=None):
        try:
            tmp_file_path = self.smb_path + '\\' + path
            matches = self.smbClient.listPath(shareName=self.smb_share, path=tmp_file_path)
            for entry in matches:
                if entry.is_directory():
                    print("[>] Skipping '%s' because it is a directory." % tmp_file_path)
                else:
                    f = LocalFileIO(
                        mode="wb", 
                        path=entry.get_longname(),
                        expected_size=entry.get_filesize(), 
                        debug=self.debug
                    )
                    self.smbClient.getFile(
                        shareName=self.smb_share, 
                        pathName=tmp_file_path, 
                        callback=f.write
                    )
                    f.close()
        except (BrokenPipeError, KeyboardInterrupt) as e:
            print("[!] Interrupted.")
            self.close_smb_session()
            self.init_smb_session()
                
        return None

    def get_file_recursively(self, path=None):

        def recurse_action(base_dir="", path=[]):
            remote_smb_path = base_dir + '\\'.join(path)
            entries = self.smbClient.listPath(shareName=self.smb_share, path=remote_smb_path+'\\*')
            if len(entries) != 0:
                files = [entry for entry in entries if not entry.is_directory()]
                directories = [entry for entry in entries if entry.is_directory() and entry.get_longname() not in [".", ".."]]

                # Files
                if len(files) != 0:
                    print("[>] Getting files of '%s'" % remote_smb_path)
                for entry_file in files:
                    if not entry_file.is_directory():
                        f = LocalFileIO(
                            mode="wb",
                            path=remote_smb_path + '\\' + entry_file.get_longname(), 
                            expected_size=entry_file.get_filesize(),
                            debug=self.debug
                        )
                        try:
                            self.smbClient.getFile(
                                shareName=self.smb_share, 
                                pathName=remote_smb_path + '\\' + entry_file.get_longname(), 
                                callback=f.write
                            )
                            f.close()
                        except Exception as err:
                            f.set_error(message="[bold red]Failed downloading '%s': %s" % (f.path, err))
                            f.close(remove=True)
                
                # Directories
                for entry_directory in directories:
                    if entry_directory.is_directory():
                        recurse_action(
                            base_dir=self.smb_path, 
                            path=path+[entry_directory.get_longname()]
                        )                   
        # Entrypoint
        try:
            recurse_action(
                base_dir=self.smb_path, 
                path=[path]
            )
        except (BrokenPipeError, KeyboardInterrupt) as e:
            print("[!] Interrupted.")
            self.close_smb_session()
            self.init_smb_session()

    def init_smb_session(self):
        if self.debug:
            print("[debug] [>] Connecting to remote SMB server '%s' ... " % self.address)
        self.smbClient = impacketSMBConnection(
            remoteName=self.address,
            remoteHost=self.address,
            sess_port=int(445)
        )

        self.connected = False
        if self.use_kerberos:
            if self.debug:
                print("[debug] [>] Authenticating as '%s\\%s' with kerberos ... " % (self.domain, self.username))
            self.connected = self.smbClient.kerberosLogin(
                user=self.username,
                password=self.password,
                domain=self.domain,
                lmhash=self.lmhash,
                nthash=self.nthash,
                aesKey=self.aesKey,
                kdcHost=self.kdcHost
            )

        else:
            if self.debug:
                print("[debug] [>] Authenticating as '%s\\%s' with NTLM ... " % (self.domain, self.username))
            self.connected = self.smbClient.login(
                user=self.username,
                password=self.password,
                domain=self.domain,
                lmhash=self.lmhash,
                nthash=self.nthash
            )

        if self.connected:
            print("[+] Successfully authenticated to '%s' as '%s\\%s'!" % (self.address, self.domain, self.username))
        else:
            print("[!] Failed to authenticate to '%s' as '%s\\%s'!" % (self.address, self.domain, self.username))

        return self.connected

    def info(self, share=True, server=True):
        if server:
            print("[+] Server:")
            print("  ├─NetBIOS:")
            print("  │ ├─ \x1b[94mNetBIOS Hostname\x1b[0m \x1b[90m────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.getServerName()))
            print("  │ └─ \x1b[94mNetBIOS Domain\x1b[0m \x1b[90m──────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.getServerDomain()))
            print("  ├─DNS:")
            print("  │ ├─ \x1b[94mDNS Hostname\x1b[0m \x1b[90m────────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.getServerDNSHostName()))
            print("  │ └─ \x1b[94mDNS Domain\x1b[0m \x1b[90m──────────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.getServerDNSDomainName()))
            print("  ├─OS:")
            print("  │ ├─ \x1b[94mOS Name\x1b[0m \x1b[90m─────────────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.getServerOS()))
            print("  │ └─ \x1b[94mOS Version\x1b[0m \x1b[90m──────────────\x1b[0m : \x1b[93m%s.%s.%s\x1b[0m" % (self.smbClient.getServerOSMajor(), self.smbClient.getServerOSMinor(), self.smbClient.getServerOSBuild()))
            print("  ├─SMB:")
            print("  │ ├─ \x1b[94mSMB Signing Required\x1b[0m \x1b[90m────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.isSigningRequired()))
            print("  │ ├─ \x1b[94mSMB Login Required\x1b[0m \x1b[90m──────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.isLoginRequired()))
            print("  │ ├─ \x1b[94mSupports NTLMv2\x1b[0m \x1b[90m─────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.doesSupportNTLMv2()))
            MaxReadSize = self.smbClient.getIOCapabilities()["MaxReadSize"]
            print("  │ ├─ \x1b[94mMax size of read chunk\x1b[0m \x1b[90m──\x1b[0m : \x1b[93m%d bytes (%s)\x1b[0m" % (MaxReadSize, b_filesize(MaxReadSize)))
            MaxWriteSize = self.smbClient.getIOCapabilities()["MaxWriteSize"]
            print("  │ └─ \x1b[94mMax size of write chunk\x1b[0m \x1b[90m─\x1b[0m : \x1b[93m%d bytes (%s)\x1b[0m" % (MaxWriteSize, b_filesize(MaxWriteSize)))
            print("  └─")

        if share and self.smb_share is not None:
            print("\n[+] Share:")
            # print("│ " % self.smbClient.queryInfo())

    def list_shares(self):
        self.shares = {}

        if not self.ping_smb_session():
            self.connected = self.init_smb_session()

        if self.connected:
            if self.smbClient is not None:
                resp = self.smbClient.listShares()

                for share in resp:
                    # SHARE_INFO_1 structure (lmshare.h)
                    # https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_1
                    sharename = share["shi1_netname"][:-1]
                    sharecomment = share["shi1_remark"][:-1]
                    sharetype = share["shi1_type"]

                    self.shares[sharename] = {
                        "name": sharename, 
                        "type": STYPE_MASK(sharetype), 
                        "rawtype": sharetype, 
                        "comment": sharecomment
                    }

            else:
                print("[!] Error: SMBSession.smbClient is None.")

        return self.shares

    def list_contents(self, shareName=None, path=None):
        if path is not None:
            self.smb_path = path
        else:
            path = self.smb_path
        
        if shareName is not None:
            self.smb_share = shareName
        else:
            shareName = self.smb_share

        path = path + "*"

        contents = {}
        for entry in self.smbClient.listPath(shareName=shareName, path=path):
            contents[entry.get_longname()] = entry

        return contents

    def mkdir(self, path=None):
        if path is not None:
            # Prepare path
            path = path.replace('/','\\')
            if '\\' in path:
                path = path.strip('\\').split('\\')
            else:
                path = [path]

            # Create each dir in the path
            for depth in range(1, len(path)+1):
                tmp_path = '\\'.join(path[:depth])
                try:
                    self.smbClient.createDirectory(
                        shareName=self.smb_share, 
                        pathName=ntpath.normpath(self.smb_path + '\\' + tmp_path + '\\')
                    )
                except impacket.smbconnection.SessionError as err:
                    if err.getErrorCode() == 0xc0000035:
                        # STATUS_OBJECT_NAME_COLLISION
                        # Remote directory already created, this is normal
                        # Src: https://github.com/fortra/impacket/blob/269ce69872f0e8f2188a80addb0c39fedfa6dcb8/impacket/nt_errors.py#L268C9-L268C19
                        pass
                    else:
                        print("[!] Failed to create directory '%s': %s" % (tmp_path, err))
                        if self.debug:
                            traceback.print_exc()
        else:
            pass

    def path_exists(self, path=None):
        if path is not None:
            path = path.replace('*','')
            try:
                contents = self.smbClient.listPath(
                    shareName=self.smb_share,
                    path=self.smb_path + '\\' + path
                )
                return (len(contents) != 0)
            except Exception as e:
                return False
        else:
            return False

    def path_isfile(self, path=None):
        if path is not None:
            path = path.replace('*','')
            try:
                contents = self.smbClient.listPath(
                    shareName=self.smb_share,
                    path=self.smb_path + '\\' + path
                )
                # Filter on files
                contents = [
                    c for c in contents
                    if c.get_longname() == ntpath.basename(path) and not c.is_directory()
                ]
                return (len(contents) != 0)
            except Exception as e:
                return False
        else:
            return False
        
    def path_isdir(self, path=None):
        if path is not None:
            path = path.replace('*','')
            try:
                contents = self.smbClient.listPath(
                    shareName=self.smb_share,
                    path=self.smb_path + '\\' + path
                )
                # Filter on directories
                contents = [
                    c for c in contents
                    if c.get_longname() == ntpath.basename(path) and c.is_directory()
                ]
                return (len(contents) != 0)
            except Exception as e:
                return False
        else:
            return False

    def ping_smb_session(self):
        try:
            self.smbClient.getSMBServer().echo()
            self.connected = True
        except Exception as e:
            self.connected = False
        return self.connected

    def put_file(self, localpath=None):
        try:
            localfile = os.path.basename(localpath)
            f = LocalFileIO(
                mode="rb", 
                path=localpath, 
                debug=self.debug
            )
            self.smbClient.putFile(
                shareName=self.smb_share, 
                pathName=self.smb_path + '\\' + localfile, 
                callback=f.read
            )
            f.close()
        except (BrokenPipeError, KeyboardInterrupt) as err:
            print("[!] Interrupted.")
            self.close_smb_session()
            self.init_smb_session()
        except Exception as err:
            print("[!] Failed to upload '%s': %s" % (localfile, err))
            if self.debug:
                traceback.print_exc()

    def put_file_recursively(self, localpath=None):
        # Check if the path is a directory
        if os.path.isdir(localpath):
            # Iterate over all files and directories within the local path
            local_files = {}
            for root, dirs, files in os.walk(localpath):
                if len(files) != 0:
                    local_files[root] = files

            # Iterate over the found files
            for local_dir_path in sorted(local_files.keys()):
                print("[>] Putting files of '%s'" % local_dir_path)

                # Create remote directory
                remote_dir_path = local_dir_path.replace(os.path.sep, '\\')
                self.mkdir(
                    path=ntpath.normpath(self.smb_path + '\\' + remote_dir_path + '\\')
                )

                for local_file_path in local_files[local_dir_path]:
                    try:
                        f = LocalFileIO(
                            mode="rb", 
                            path=local_dir_path + os.path.sep + local_file_path, 
                            debug=self.debug
                        )
                        self.smbClient.putFile(
                            shareName=self.smb_share, 
                            pathName=ntpath.normpath(self.smb_path + '\\' + remote_dir_path + '\\' + local_file_path), 
                            callback=f.read
                        )
                        f.close()
                    except Exception as err:
                        print("[!] Failed to upload '%s': %s" % (local_file_path, err))
                        if self.debug:
                            traceback.print_exc()
        else:
            print("[!] The specified localpath is not a directory.")

    def tree(self, path=None):
        #
        def recurse_action(base_dir="", path=[], prompt=[]):
            bars = ["│   ", "├── ", "└── "]

            remote_smb_path = base_dir + '\\'.join(path)

            entries = self.smbClient.listPath(
                shareName=self.smb_share, 
                path=remote_smb_path+'\\*'
            )
            entries = [e for e in entries if e.get_longname() not in [".", ".."]]
            entries = sorted(entries, key=lambda x:x.get_longname())

            # 
            if len(entries) > 1:
                index = 0
                for entry in entries:
                    index += 1
                    # This is the first entry 
                    if index == 0:
                        if entry.is_directory():
                            print("%s\x1b[1;96m%s\x1b[0m\\" % (''.join(prompt+[bars[1]]), entry.get_longname()))
                            recurse_action(
                                base_dir=self.smb_path, 
                                path=path+[entry.get_longname()],
                                prompt=prompt+["│   "]
                            )
                        else:
                            print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[1]]), entry.get_longname()))

                    # This is the last entry
                    elif index == len(entries):
                        if entry.is_directory():
                            print("%s\x1b[1;96m%s\x1b[0m\\" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                            recurse_action(
                                base_dir=self.smb_path, 
                                path=path+[entry.get_longname()],
                                prompt=prompt+["    "]
                            )
                        else:
                            print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                        
                    # These are entries in the middle
                    else:
                        if entry.is_directory():
                            print("%s\x1b[1;96m%s\x1b[0m\\" % (''.join(prompt+[bars[1]]), entry.get_longname()))
                            recurse_action(
                                base_dir=self.smb_path, 
                                path=path+[entry.get_longname()],
                                prompt=prompt+["│   "]
                            )
                        else:
                            print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[1]]), entry.get_longname()))

            # 
            elif len(entries) == 1:
                entry = entries[0]
                if entry.is_directory():
                    print("%s\x1b[1;96m%s\x1b[0m\\" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                    recurse_action(
                        base_dir=self.smb_path, 
                        path=path+[entry.get_longname()],
                        prompt=prompt+["    "]
                    )
                else:
                    print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[2]]), entry.get_longname()))

        # Entrypoint
        try:
            path = ntpath.normpath(path)
            print("\x1b[1;96m%s\x1b[0m\\" % path)
            recurse_action(
                base_dir=self.smb_path, 
                path=[path],
                prompt=[""]
            )
        except (BrokenPipeError, KeyboardInterrupt) as e:
            print("[!] Interrupted.")
            self.close_smb_session()
            self.init_smb_session()


def parseArgs():
    print("""               _          _ _            _                    
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _ 
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                         %10s  |___/  
    """ % ("v"+VERSION))

    parser = argparse.ArgumentParser(add_help=True, description="smbclient-ng, a fast and user friendly way to interact with SMB shares.")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode")

    parser.add_argument("--target", action="store", metavar="ip address", required=True, type=str, help="IP Address of the SMB Server to connect to.")  

    authconn = parser.add_argument_group("Authentication & connection")
    authconn.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.")
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="NT/LM hashes, format is LMhash:NThash")
    cred.add_argument("--aes-key", dest="auth_key", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    return args


if __name__ == "__main__":
    options = parseArgs()

    # Parse hashes
    if options.auth_hashes is not None:
        if ":" not in options.auth_hashes:
            options.auth_hashes = ":" + options.auth_hashes
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(options.auth_hashes)

    # Use AES Authentication key if available
    if options.auth_key is not None:
        options.use_kerberos = True
    if options.use_kerberos is True and options.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()

    smbSession = SMBSession(
        address=options.target,
        domain=options.auth_domain,
        username=options.auth_username,
        password=options.auth_password,
        lmhash=auth_lm_hash,
        nthash=auth_nt_hash,
        use_kerberos=options.use_kerberos,
        debug=options.debug
    )
    smbSession.init_smb_session()

    shell = InteractiveShell(smbSession=smbSession, debug=options.debug)
    shell.run()