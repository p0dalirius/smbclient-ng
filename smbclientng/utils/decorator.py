#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : decorator.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

## Decorators

def command_arguments_required(func):
    """
    Decorator to check if the command has arguments.
    """
    def wrapper(*args, **kwargs):
        self, arguments,command  = args[0], args[1], args[2]
        if len(arguments) != 0:
            return func(*args, **kwargs)
        else:
            self.commandCompleterObject.print_help(command=command)
            return None
    return wrapper

def active_smb_connection_needed(func):
    """
    Decorator to check if the SMB connection is active.
    """
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
    """
    Decorator to check if the SMB share is set.
    """
    def wrapper(*args, **kwargs):
        self, arguments,command  = args[0], args[1], args[2]
        if self.sessionsManager.current_session.smb_share is not None:
            return func(*args, **kwargs)
        else:
            self.logger.error("You must open a share first, try the 'use <share>' command.")
            return None
    return wrapper