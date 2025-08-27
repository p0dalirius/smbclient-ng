#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : InteractiveShell.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024

from __future__ import annotations

import ntpath
import os
import readline
import shlex
import sys
import traceback
from importlib import import_module
from typing import TYPE_CHECKING
from datetime import datetime

import smbclientng.commands as commands
from smbclientng.core.CommandCompleter import CommandCompleter

if TYPE_CHECKING:
    from smbclientng.core.Logger import Logger
    from smbclientng.core.SessionsManager import SessionsManager
    from smbclientng.types.Config import Config


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

    commands = {
        "acls": commands.Command_acls,
        "bat": commands.Command_bat,
        "bhead": commands.Command_bhead,
        "btail": commands.Command_btail,
        "cat": commands.Command_cat,
        "cd": commands.Command_cd,
        "close": commands.Command_close,
        "dir": commands.Command_dir,
        "exit": commands.Command_exit,
        "find": commands.Command_find,
        "get": commands.Command_get,
        "help": commands.Command_help,
        "head": commands.Command_head,
        "history": commands.Command_history,
        "info": commands.Command_info,
        "lbat": commands.Command_lbat,
        "lcat": commands.Command_lcat,
        "lcd": commands.Command_lcd,
        "lcp": commands.Command_lcp,
        "lls": commands.Command_lls,
        "lmkdir": commands.Command_lmkdir,
        "lpwd": commands.Command_lpwd,
        "lrename": commands.Command_lrename,
        "lrmdir": commands.Command_lrmdir,
        "lrm": commands.Command_lrm,
        "ls": commands.Command_ls,
        "ltree": commands.Command_ltree,
        "metadata": commands.Command_metadata,
        "mkdir": commands.Command_mkdir,
        "module": commands.Command_module,
        "mount": commands.Command_mount,
        "put": commands.Command_put,
        "reconnect": commands.Command_reconnect,
        "reset": commands.Command_reset,
        "rmdir": commands.Command_rmdir,
        "rm": commands.Command_rm,
        "sessions": commands.Command_sessions,
        "shares": commands.Command_shares,
        "sizeof": commands.Command_sizeof,
        "tail": commands.Command_tail,
        "tree": commands.Command_tree,
        "umount": commands.Command_umount,
        "use": commands.Command_use,
        "quit": commands.Command_quit,
    }

    def __init__(
        self, sessionsManager: SessionsManager, config: Config, logger: Logger
    ):
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
        # History with timestamps: list of tuples (datetime, command_line)
        self.history: list[tuple[datetime, str]] = []
        # Additional modules
        self.__load_modules()

    def run(self):
        pre_interaction_commands = []

        # Read commands from script file first
        if self.config.startup_script:
            with open(self.config.startup_script, "r") as f:
                pre_interaction_commands = f.readlines()

        # Add commands specified from command line
        if len(self.config.commands) > 0:
            pre_interaction_commands += self.config.commands

        # Execute pre-interaction commands
        if len(pre_interaction_commands) > 0:
            for line in pre_interaction_commands:
                try:
                    line_stripped = line.strip()
                    self.logger.print("%s%s" % (self.__prompt(), line_stripped))
                    self.__record_history_entry(line_stripped)
                    self.process_line(commandLine=line_stripped)
                except KeyboardInterrupt:
                    self.logger.print()

                except EOFError:
                    self.logger.print()
                    self.running = False

                except Exception as err:
                    if self.config.debug:
                        traceback.print_exc()
                    self.logger.error(str(err))

        # Then interactive console
        if not self.config.not_interactive:
            while self.running:
                try:
                    user_input = input(self.__prompt()).strip()
                    # Record history and write to logfile
                    if len(user_input) > 0:
                        self.__record_history_entry(user_input)
                    self.logger.write_to_logfile(self.__prompt() + user_input)
                    self.process_line(commandLine=user_input)
                except KeyboardInterrupt:
                    self.logger.print()

                except EOFError:
                    self.logger.print()
                    self.running = False

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
        elif command in self.commands.keys():
            command_instance = self.commands[command](
                smbSession=self.sessionsManager.current_session,
                config=self.config,
                logger=self.logger,
            )
            command_instance.run(self, arguments, command)
            del command_instance

        # Fallback to unknown command
        else:
            self.logger.print('Unknown command. Type "help" for help.')

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

        modules_dir = os.path.normpath(
            os.path.dirname(__file__) + os.path.sep + ".." + os.path.sep + "modules"
        )
        self.logger.debug("[>] Loading modules from %s ..." % modules_dir)
        sys.path.extend([modules_dir])

        for file in os.listdir(modules_dir):
            filepath = os.path.normpath(modules_dir + os.path.sep + file)
            if file.endswith(".py"):
                if os.path.isfile(filepath) and file not in ["__init__.py"]:
                    try:
                        module_file = import_module(
                            "smbclientng.modules.%s" % (file[:-3])
                        )
                        module = module_file.__getattribute__(file[:-3])
                        self.modules[module.name.lower()] = module
                    except AttributeError:
                        pass
                    except ImportError as err:
                        self.logger.debug(
                            "[!] Could not load module '%s': %s" % ((file[:-3]), err)
                        )

        if self.config.debug:
            if len(self.modules.keys()) == 0:
                self.logger.debug("[>] Loaded 0 modules.")
            elif len(self.modules.keys()) == 1:
                self.logger.debug("[>] Loaded 1 module:")
            else:
                self.logger.debug("[>] Loaded %d modules:" % len(self.modules.keys()))
            for modulename in sorted(self.modules.keys()):
                self.logger.debug(
                    '  | %s : "%s" (%s)'
                    % (
                        self.modules[modulename].name,
                        self.modules[modulename].description,
                        self.modules[modulename],
                    )
                )

        if self.commandCompleterObject is not None:
            self.commandCompleterObject.commands["module"]["subcommands"] = list(
                self.modules.keys()
            )

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
                    current_path = (
                        self.sessionsManager.current_session.smb_cwd.strip(ntpath.sep)
                        + ntpath.sep
                    )

                str_path = "\\\\%s\\%s\\%s" % (
                    self.sessionsManager.current_session.host,
                    self.sessionsManager.current_session.smb_share,
                    current_path,
                )
        # No active session
        else:
            connected_dot = ""
            session_prompt = ""
            str_path = "No active session"

        # Build final prompt string
        if self.config.no_colors:
            str_prompt = "%s%s[%s]> " % (connected_dot, session_prompt, str_path)
        else:
            str_prompt = "%s%s[\x1b[1;94m%s\x1b[0m]> " % (
                connected_dot,
                session_prompt,
                str_path,
            )

        return str_prompt

    def __record_history_entry(self, command_line: str):
        """Record a command in both the in-memory timestamped history and readline."""
        if command_line is None:
            return
        command_line = command_line.strip()
        if len(command_line) == 0:
            return
        # Save in-memory with timestamp
        self.history.append((datetime.now(), command_line))
        # Also push to readline for compatibility with shell shortcuts
        try:
            readline.add_history(command_line)
        except Exception:
            pass
