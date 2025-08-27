#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : decorator.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025


def command_arguments_required(func):
    """
    Decorator to check if the command has arguments.
    """

    def wrapper(*args, **kwargs):
        # self, interactive_shell, arguments, command
        interactive_shell = args[1]
        arguments = args[2]
        command = args[3]
        if len(arguments) != 0:
            return func(*args, **kwargs)
        else:
            interactive_shell.commandCompleterObject.print_help(command=command)
            return None

    return wrapper


def active_smb_connection_needed(func):
    """
    Decorator to check if the SMB connection is active.
    """

    def wrapper(*args, **kwargs):
        # self, interactive_shell, arguments, command
        interactive_shell = args[1]

        if interactive_shell.sessionsManager.current_session is None:
            interactive_shell.logger.error("SMB Session is disconnected.")
            return None

        interactive_shell.sessionsManager.current_session.ping_smb_session()
        if interactive_shell.sessionsManager.current_session.connected:
            return func(*args, **kwargs)
        else:
            interactive_shell.logger.error("SMB Session is disconnected.")
            return None

    return wrapper


def smb_share_is_set(func):
    """
    Decorator to check if the SMB share is set.
    """

    def wrapper(*args, **kwargs):
        # self, interactive_shell, arguments, command
        interactive_shell = args[1]
        if interactive_shell.sessionsManager.current_session.smb_share is not None:
            return func(*args, **kwargs)
        else:
            interactive_shell.logger.error(
                "You must open a share first, try the 'use <share>' command."
            )
            return None

    return wrapper
