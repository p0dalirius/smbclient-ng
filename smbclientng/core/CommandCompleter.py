# -*- coding: utf-8 -*-
# File name          : CommandCompleter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 mar 2025

from __future__ import annotations

import ntpath
import os
import shlex
from typing import TYPE_CHECKING

from smbclientng.commands import (Command_acls, Command_bat, Command_bhead,
                                  Command_btail, Command_cat, Command_cd,
                                  Command_close, Command_dir, Command_exit,
                                  Command_find, Command_get, Command_head,
                                  Command_help, Command_history, Command_info,
                                  Command_lbat, Command_lcat, Command_lcd,
                                  Command_lcp, Command_lls, Command_lmkdir,
                                  Command_lpwd, Command_lrename, Command_lrm,
                                  Command_lrmdir, Command_ls, Command_ltree,
                                  Command_metadata, Command_mkdir,
                                  Command_module, Command_mount, Command_put,
                                  Command_quit, Command_reconnect,
                                  Command_reset, Command_rm, Command_rmdir,
                                  Command_sessions, Command_shares,
                                  Command_sizeof, Command_tail, Command_tree,
                                  Command_umount, Command_use)

if TYPE_CHECKING:
    from typing import Optional

    from smbclientng.core.Config import Config
    from smbclientng.core.Logger import Logger
    from smbclientng.core.SMBSession import SMBSession


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

    commands: dict = {
        "acls": Command_acls.HELP,
        "bat": Command_bat.HELP,
        "bhead": Command_bhead.HELP,
        "btail": Command_btail.HELP,
        "cat": Command_cat.HELP,
        "cd": Command_cd.HELP,
        "close": Command_close.HELP,
        "dir": Command_dir.HELP,
        "exit": Command_exit.HELP,
        "find": Command_find.HELP,
        "get": Command_get.HELP,
        "help": Command_help.HELP,
        "head": Command_head.HELP,
        "history": Command_history.HELP,
        "info": Command_info.HELP,
        "lbat": Command_lbat.HELP,
        "lcat": Command_lcat.HELP,
        "lcd": Command_lcd.HELP,
        "lcp": Command_lcp.HELP,
        "lls": Command_lls.HELP,
        "lmkdir": Command_lmkdir.HELP,
        "lpwd": Command_lpwd.HELP,
        "lrename": Command_lrename.HELP,
        "lrmdir": Command_lrmdir.HELP,
        "lrm": Command_lrm.HELP,
        "ls": Command_ls.HELP,
        "ltree": Command_ltree.HELP,
        "metadata": Command_metadata.HELP,
        "mkdir": Command_mkdir.HELP,
        "module": Command_module.HELP,
        "mount": Command_mount.HELP,
        "put": Command_put.HELP,
        "reconnect": Command_reconnect.HELP,
        "reset": Command_reset.HELP,
        "rmdir": Command_rmdir.HELP,
        "rm": Command_rm.HELP,
        "sessions": Command_sessions.HELP,
        "shares": Command_shares.HELP,
        "sizeof": Command_sizeof.HELP,
        "tail": Command_tail.HELP,
        "tree": Command_tree.HELP,
        "umount": Command_umount.HELP,
        "use": Command_use.HELP,
        "quit": Command_quit.HELP,
    }

    smbSession: SMBSession
    config: Config
    logger: Logger

    def __init__(self, smbSession: SMBSession, config: Config, logger: Logger):
        # Objects
        self.smbSession = smbSession
        self.config = config
        self.logger = logger
        # Pre computing for some commands
        self.commands["help"]["subcommands"] = ["format"] + list(self.commands.keys())
        self.commands["help"]["subcommands"].remove("help")

    def complete(self, text: str, state: int) -> str:
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

            # Parsing a command
            elif len(text) != 0:
                # This is for the main command
                if text.count(" ") == 0:
                    self.matches = [
                        s for s in self.commands.keys() if s and s.startswith(text)
                    ]

                # This is for subcommands
                elif text.count(" ") >= 1:
                    command, remainder = text.split(" ", 1)

                    if command in self.commands.keys():
                        self.matches = []

                        # Autocomplete shares
                        if "share" in self.commands[command]["autocomplete"]:
                            # Choose SMB Share to connect to
                            shares = self.smbSession.list_shares()
                            matching_entries = []
                            for sharename in shares.keys():
                                if sharename.lower().startswith(remainder.lower()):
                                    matching_entries.append(shares[sharename]["name"])
                            # Final matches
                            for m in matching_entries:
                                self.matches.append(command + " " + shlex.quote(m))

                        # Autocomplete directory
                        if "remote_directory" in self.commands[command]["autocomplete"]:
                            # Choose remote directory
                            path = ""
                            if "\\" in remainder.strip() or "/" in remainder.strip():
                                path = remainder.strip().replace(ntpath.sep, "/")
                                path = "/".join(path.split("/")[:-1])
                            # Get remote directory contents
                            directory_contents = self.smbSession.list_contents(
                                path=path
                            ).items()
                            #
                            matching_entries = []
                            for _, entry in directory_contents:
                                if (
                                    entry.is_directory()
                                    and entry.get_longname() not in [".", ".."]
                                ):
                                    if len(path) != 0:
                                        matching_entries.append(
                                            path + "/" + entry.get_longname() + "/"
                                        )
                                    else:
                                        matching_entries.append(
                                            entry.get_longname() + "/"
                                        )
                            #
                            for m in matching_entries:
                                if m.lower().startswith(
                                    remainder.lower()
                                ) or shlex.quote(m).lower().startswith(
                                    remainder.lower()
                                ):
                                    self.matches.append(command + " " + shlex.quote(m))

                        # Autocomplete file
                        if "remote_file" in self.commands[command]["autocomplete"]:
                            # Choose remote file
                            path = ""
                            if "\\" in remainder.strip() or "/" in remainder.strip():
                                path = remainder.strip().replace(ntpath.sep, "/")
                                path = "/".join(path.split("/")[:-1])
                            # Get remote directory contents
                            directory_contents = self.smbSession.list_contents(
                                path=path
                            ).items()
                            #
                            matching_entries = []
                            for _, entry in directory_contents:
                                if (
                                    not entry.is_directory()
                                ) and entry.get_longname() not in [".", ".."]:
                                    if len(path) != 0:
                                        matching_entries.append(
                                            path + "/" + entry.get_longname()
                                        )
                                    else:
                                        matching_entries.append(entry.get_longname())
                            #
                            for m in matching_entries:
                                if m.lower().startswith(
                                    remainder.lower()
                                ) or shlex.quote(m).lower().startswith(
                                    remainder.lower()
                                ):
                                    self.matches.append(command + " " + shlex.quote(m))

                        # Autocomplete local_directory
                        if "local_directory" in self.commands[command]["autocomplete"]:
                            # Choose directory
                            path = ""
                            if os.path.sep in remainder.strip():
                                path = path.split(os.path.sep)[:-1]
                                path = os.path.sep.join(path)
                            # Current dir
                            if len(path.strip()) == 0:
                                path = "."
                            #
                            directory_contents = os.listdir(path=path + os.path.sep)
                            matching_entries = []
                            for entry in directory_contents:
                                if entry not in [".", ".."]:
                                    entry_path = path + os.path.sep + entry
                                    if os.path.isdir(entry_path):
                                        matching_entries.append(
                                            entry_path + os.path.sep
                                        )
                            #
                            for m in matching_entries:
                                if m.lower().startswith(
                                    remainder.lower()
                                ) or shlex.quote(m).lower().startswith(
                                    remainder.lower()
                                ):
                                    self.matches.append(command + " " + shlex.quote(m))

                        # Autocomplete local_file
                        if "local_file" in self.commands[command]["autocomplete"]:
                            # Choose file
                            path = ""
                            if os.path.sep in remainder.strip():
                                path = path.split(os.path.sep)[:-1]
                                path = os.path.sep.join(path)
                            # Current dir
                            if len(path.strip()) == 0:
                                path = "."
                            #
                            directory_contents = os.listdir(path=(path + os.path.sep))
                            matching_entries = []
                            for entry in directory_contents:
                                if entry not in [".", ".."]:
                                    entry_path = path + os.path.sep + entry
                                    if not os.path.isdir(entry_path):
                                        matching_entries.append(entry_path)
                            #
                            for m in matching_entries:
                                if m.lower().startswith(
                                    remainder.lower()
                                ) or shlex.quote(m).lower().startswith(
                                    remainder.lower()
                                ):
                                    self.matches.append(command + " " + shlex.quote(m))

                        else:
                            # Generic case for subcommands
                            for m in self.commands[command]["subcommands"]:
                                if m.startswith(remainder):
                                    self.matches.append(command + " " + m)
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

    def print_help(self, command: Optional[str] = None):
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
            if command not in list(self.commands.keys()) + ["format"]:
                self.logger.error("Help for command '%s' does not exist." % command)
                return

        # Print help for a specific command
        if command is not None:
            if command == "format":
                self.print_help_format()
            else:
                self.logger.print("│")
                if self.config.no_colors:
                    command_str = command + "─" * (15 - len(command))
                    if len(self.commands[command]["description"]) == 0:
                        self.logger.print("│ ■ %s┤  " % command_str)
                    elif len(self.commands[command]["description"]) == 1:
                        self.logger.print(
                            "│ ■ %s┤ %s "
                            % (command_str, self.commands[command]["description"][0])
                        )
                    else:
                        self.logger.print(
                            "│ ■ %s┤ %s "
                            % (command_str, self.commands[command]["description"][0])
                        )
                        for line in self.commands[command]["description"][1:]:
                            self.logger.print("│ %s│ %s " % (" " * (15 + 2), line))
                else:
                    command_str = (
                        command + " \x1b[90m" + "─" * (15 - len(command)) + "\x1b[0m"
                    )
                    if len(self.commands[command]["description"]) == 0:
                        self.logger.print("│ ■ %s\x1b[90m┤\x1b[0m  " % command_str)
                    elif len(self.commands[command]["description"]) == 1:
                        self.logger.print(
                            "│ ■ %s\x1b[90m┤\x1b[0m %s "
                            % (command_str, self.commands[command]["description"][0])
                        )
                    else:
                        self.logger.print(
                            "│ ■ %s\x1b[90m┤\x1b[0m %s "
                            % (command_str, self.commands[command]["description"][0])
                        )
                        for line in self.commands[command]["description"][1:]:
                            self.logger.print(
                                "│ %s\x1b[90m│\x1b[0m %s " % (" " * (15 + 3), line)
                            )
                self.logger.print("│")
        # Generic help
        else:
            self.logger.print("│")
            commands = sorted(self.commands.keys())
            for command in commands:
                if self.config.no_colors:
                    command_str = command + "─" * (15 - len(command))
                    if len(self.commands[command]["description"]) == 0:
                        self.logger.print("│ ■ %s┤  " % command_str)
                    elif len(self.commands[command]["description"]) == 1:
                        self.logger.print(
                            "│ ■ %s┤ %s "
                            % (command_str, self.commands[command]["description"][0])
                        )
                    else:
                        self.logger.print(
                            "│ ■ %s┤ %s "
                            % (command_str, self.commands[command]["description"][0])
                        )
                        for line in self.commands[command]["description"][1:]:
                            self.logger.print("│ %s│ %s " % (" " * (15 + 2), line))
                else:
                    command_str = (
                        command + " \x1b[90m" + "─" * (15 - len(command)) + "\x1b[0m"
                    )
                    if len(self.commands[command]["description"]) == 0:
                        self.logger.print("│ ■ %s\x1b[90m┤\x1b[0m  " % command_str)
                    elif len(self.commands[command]["description"]) == 1:
                        self.logger.print(
                            "│ ■ %s\x1b[90m┤\x1b[0m %s "
                            % (command_str, self.commands[command]["description"][0])
                        )
                    else:
                        self.logger.print(
                            "│ ■ %s\x1b[90m┤\x1b[0m %s "
                            % (command_str, self.commands[command]["description"][0])
                        )
                        for line in self.commands[command]["description"][1:]:
                            self.logger.print(
                                "│ %s\x1b[90m│\x1b[0m %s " % (" " * (15 + 3), line)
                            )
                self.logger.print("│")

    def print_help_format(self):
        """
        Prints the help information for the 'format' used in remote 'ls' and 'dir' commands.

        This function displays the format of file attributes used in the smbclient-ng shell. It explains the meaning
        of each character in the file attribute string, such as whether a file is read-only, hidden, or a directory.
        """
        if self.config.no_colors:
            self.logger.print("File attributes format:\n")
            self.logger.print("dachnrst")
            self.logger.print("│││││││└──> Temporary")
            self.logger.print("││││││└───> System")
            self.logger.print("│││││└────> Read-Only")
            self.logger.print("││││└─────> Normal")
            self.logger.print("│││└──────> Hidden")
            self.logger.print("││└───────> Compressed")
            self.logger.print("│└────────> Archived")
            self.logger.print("└─────────> Directory")
        else:
            self.logger.print("File attributes format:\n")
            self.logger.print("dachnrst")
            self.logger.print("\x1b[90m│││││││└──>\x1b[0m Temporary")
            self.logger.print("\x1b[90m││││││└───>\x1b[0m System")
            self.logger.print("\x1b[90m│││││└────>\x1b[0m Read-Only")
            self.logger.print("\x1b[90m││││└─────>\x1b[0m Normal")
            self.logger.print("\x1b[90m│││└──────>\x1b[0m Hidden")
            self.logger.print("\x1b[90m││└───────>\x1b[0m Compressed")
            self.logger.print("\x1b[90m│└────────>\x1b[0m Archived")
            self.logger.print("\x1b[90m└─────────>\x1b[0m Directory")
