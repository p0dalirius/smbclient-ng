#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : CommandCompleter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 may 2024


import ntpath
import os


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

    commands = {
        "bat": {
            "description": [
                "Pretty prints the contents of a file.", 
                "Syntax: 'bat <file>'"
            ], 
            "subcommands": []
        },
        "cat": {
            "description": [
                "Get the contents of a file.", 
                "Syntax: 'cat <file>'"
            ], 
            "subcommands": []
        },
        "cd": {
            "description": [
                "Change the current working directory.", 
                "Syntax: 'cd <directory>'"
            ], 
            "subcommands": []
        },
        "close": {
            "description": [
                "Closes the SMB connection to the remote machine.", 
                "Syntax: 'close'"
            ], 
            "subcommands": []
        },
        "connect": {
            "description": [
                "Connect to the remote machine (useful if connection timed out).", 
                "Syntax: 'connect'"
            ], 
            "subcommands": []
        },
        "debug": {
            "description": [
                "Command for dev debugging.",
                "Syntax: 'debug'"
            ], 
            "subcommands": []
        },
        "dir": {
            "description": [
                "List the contents of the current working directory.",
                "Syntax: 'dir'"
            ], 
            "subcommands": []
        },
        "exit": {
            "description": [
                "Exits the smbclient-ng script.",
                "Syntax: 'exit'"
            ], 
            "subcommands": []
        },
        "get": {
            "description": [
                "Get a remote file.",
                "Syntax: 'get [-r] <directory or file>'"
            ], 
            "subcommands": []
        },
        "help": {
            "description": [
                "Displays this help message.",
                "Syntax: 'help'"
            ], 
            "subcommands": ["format"]
        },
        "info": {
            "description": [
                "Get information about the server and or the share.",
                "Syntax: 'info [server|share]'"
            ], 
            "subcommands": ["server", "share"]
        },
        "lcd": {
            "description": [
                "Changes the current local directory.",
                "Syntax: 'lcd <directory>'"
            ], 
            "subcommands": []
        },
        "lcp": {
            "description": [
                "Create a copy of a local file.",
                "Syntax: 'lcp <srcfile> <dstfile>'"
            ], 
            "subcommands": []
        },
        "lls": {
            "description": [
                "Lists the contents of the current local directory.", 
                "Syntax: 'lls'"
            ],
            "subcommands": []
        },
        "lmkdir": {
            "description": [
                "Creates a new local directory.", 
                "Syntax: 'lmkdir <directory>'"
            ],
            "subcommands": []
        },
        "lpwd": {
            "description": [
                "Shows the current local directory.", 
                "Syntax: 'lpwd'"
            ],
            "subcommands": []
        },
        "lrename": {
            "description": [
                "Renames a local file.", 
                "Syntax: 'lrename <oldfilename> <newfilename>'"
            ], 
            "subcommands": []
        },
        "lrm": {
            "description": [
                "Removes a local file.", 
                "Syntax: 'lrm <file>'"
            ], 
            "subcommands": []
        },
        "lrmdir": {
            "description": [
                "Removes a local directory.", 
                "Syntax: 'lrmdir <directory>'"
            ], 
            "subcommands": []
        },
        "ls": {
            "description": [
                "List the contents of the current remote working directory.", 
                "Syntax: 'ls'"
            ], 
            "subcommands": []
        },
        "ltree": {
            "description": [
                "Displays a tree view of the local directories.",
                "Syntax: 'ltree [directory]'"
            ], 
            "subcommands": []
        },
        "mkdir": {
            "description": [
                "Creates a new remote directory.", 
                "Syntax: 'mkdir <directory>'"
            ], 
            "subcommands": []
        },
        "module": {
            "description": [
                "Loads a specific module for additional functionalities.",
                "Syntax: 'module <name>'"
            ], 
            "subcommands": []
        },
        "put": {
            "description": [
                "Put a local file or directory in a remote directory.", 
                "Syntax: 'put [-r] <directory or file>'"
            ], 
            "subcommands": []
        },
        "reconnect": {
            "description": [
                "Reconnect to the remote machine (useful if connection timed out).", 
                "Syntax: 'reconnect'"
            ], 
            "subcommands": []
        },
        "reset": {
            "description": [
                "Reset the TTY output, useful if it was broken after printing a binary file on stdout.",
                "Syntax: 'reset'"
            ], 
            "subcommands": []
        },
        "rmdir": {
            "description": [
                "Removes a remote directory.", 
                "Syntax: 'rmdir <directory>'"
            ], 
            "subcommands": []
        },
        "rm": {
            "description": [
                "Removes a remote file.", 
                "Syntax: 'rm <file>'"
            ], 
            "subcommands": []
        },
        "sizeof": {
            "description": [
                "Recursively compute the size of a folder.", 
                "Syntax: 'sizeof [directory|file]'"
            ], 
            "subcommands": []
        },
        "shares": {
            "description": [
                "Lists the SMB shares served by the remote machine.", 
                "Syntax: 'shares'"
            ], 
            "subcommands": []
        },
        "use": {
            "description": [
                "Use a SMB share.", 
                "Syntax: 'use <sharename>'"
            ], 
            "subcommands": []
        },
        "tree": {
            "description": [
                "Displays a tree view of the remote directories.",
                "Syntax: 'tree [directory]'"
            ], 
            "subcommands": []
        },
    }

    def __init__(self, smbSession, config):
        # Objects
        self.smbSession = smbSession
        self.config = config
        # Pre computing for some commands 
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
                            self.matches = [
                                command + " " + s.lower()
                                for s in self.smbSession.list_shares().keys()
                                if s.lower().startswith(remainder.lower())
                            ]

                        elif command in ["cd", "dir", "ls", "mkdir", "rmdir", "tree"]:
                            # Choose remote directory
                            path = ""
                            if '\\' in remainder.strip() or '/' in remainder.strip():
                                path = remainder.strip().replace('/', ntpath.sep)
                                path = ntpath.sep.join(path.split(ntpath.sep)[:-1]) 

                            directory_contents = self.smbSession.list_contents(path=path).items()

                            matching_entries = []
                            for _, entry in directory_contents:
                                if entry.is_directory() and entry.get_longname() not in [".",".."]:
                                    if len(path) != 0:
                                        matching_entries.append(path + ntpath.sep + entry.get_longname() + ntpath.sep)
                                    else:
                                        matching_entries.append(entry.get_longname() + ntpath.sep)

                            self.matches = [
                                command + " " + s 
                                for s in matching_entries
                                if s.lower().startswith(remainder.lower())
                            ]

                        elif command in ["bat", "cat", "debug", "get", "rm"]:
                            # Choose local files and directories
                            path = ""
                            if '\\' in remainder.strip() or '/' in remainder.strip():
                                path = remainder.strip().replace('/', ntpath.sep)
                                path = ntpath.sep.join(path.split(ntpath.sep)[:-1]) 

                            directory_contents = self.smbSession.list_contents(path=path).items()

                            matching_entries = []
                            for _, entry in directory_contents:
                                if entry.get_longname() not in [".",".."]:
                                    if len(path) != 0:
                                        if entry.is_directory():
                                            matching_entries.append(path + ntpath.sep + entry.get_longname() + ntpath.sep)
                                        else:
                                            matching_entries.append(path + ntpath.sep + entry.get_longname())
                                    else:
                                        if entry.is_directory():
                                            matching_entries.append(entry.get_longname() + ntpath.sep)
                                        else:
                                            matching_entries.append(entry.get_longname())

                            self.matches = [
                                command + " " + s 
                                for s in matching_entries
                                if s.lower().startswith(remainder.lower())
                            ]

                        elif command in ["lcd", "lcp", "lls", "lrm", "put", "lmkdir", "lrm", "lrmdir"]:
                            # Choose directory
                            path = ""
                            if os.path.sep in remainder.strip():
                                path = path.split(os.path.sep)[:-1]
                                path = os.path.sep.join(path)
                            
                            # Current dir
                            if len(path.strip()) == 0:
                                path = "."

                            directory_contents = os.listdir(path=path + os.path.sep)
                            matching_entries = []
                            for entry in directory_contents:
                                if entry not in [".",".."]:
                                    entry_path = path + os.path.sep + entry
                                    if os.path.isdir(entry_path):
                                        matching_entries.append(entry_path + os.path.sep)
                                    else:
                                        matching_entries.append(entry_path)

                            self.matches = [
                                command + " " + s
                                for s in matching_entries
                                if s.startswith(remainder)
                            ]
                            
                        else:
                            # Generic case for subcommands
                            self.matches = [
                                command + " " + s
                                for s in self.commands[command]["subcommands"]
                                if s.startswith(remainder)
                            ]
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
        """
        Prints help information for a specific command or all commands if no command is specified.

        This method displays the help information for the command passed as an argument. If no command is specified,
        it prints the help information for all available commands. The help information includes the command syntax,
        description, and any subcommands associated with it. This method is designed to provide users with the necessary
        guidance on how to use the commands in the smbclient-ng shell.

        Args:
            command (str, optional): The command to display help information for. If None, help for all commands is displayed.

        Returns:
            None
        """

        if command is not None:
            if command not in list(self.commands.keys())+["format"]:
                command = None
        
        # Print help for a specific command
        if command is not None:
            if command == "format":
                self.print_help_format()
            else:
                print("│")
                if self.config.no_colors:
                    command_str = command + "─"* (15 - len(command))
                    if len(self.commands[command]["description"]) == 0:
                        print("│ ■ %s┤  " % command_str)
                    elif len(self.commands[command]["description"]) == 1:
                        print("│ ■ %s┤ %s " % (command_str, self.commands[command]["description"][0]))
                    else:
                        print("│ ■ %s┤ %s " % (command_str, self.commands[command]["description"][0]))
                        for line in self.commands[command]["description"][1:]:
                            print("│ %s│ %s " % (" "*(15+2), line))
                else:
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
        # Generic help
        else:
            print("│")
            commands = sorted(self.commands.keys())
            for command in commands:
                if self.config.no_colors:
                    command_str = command + "─"* (15 - len(command))
                    if len(self.commands[command]["description"]) == 0:
                        print("│ ■ %s┤  " % command_str)
                    elif len(self.commands[command]["description"]) == 1:
                        print("│ ■ %s┤ %s " % (command_str, self.commands[command]["description"][0]))
                    else:
                        print("│ ■ %s┤ %s " % (command_str, self.commands[command]["description"][0]))
                        for line in self.commands[command]["description"][1:]:
                            print("│ %s│ %s " % (" "*(15+2), line))
                else:
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
        """
        Prints the help information for the 'format' used in remote 'ls' and 'dir' commands.

        This function displays the format of file attributes used in the smbclient-ng shell. It explains the meaning
        of each character in the file attribute string, such as whether a file is read-only, hidden, or a directory.
        """

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

