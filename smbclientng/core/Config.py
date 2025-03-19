#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Config.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 mar 2025

import platform


class Config(object):
    """
    Configuration handler for smbclientng.

    This class manages the configuration settings for the smbclientng tool, including debug and color output settings.
    It provides a structured way to access and modify these settings throughout the application.

    Attributes:
        _debug (bool): Flag to enable or disable debug mode.
        _no_colors (bool): Flag to enable or disable colored output, depending on the platform.

    Methods:
        debug: Property to get or set the debug mode.
        no_colors: Property to get or set the colored output preference.
    """

    not_interactive: bool = False
    startup_script = None
    _debug: bool
    _no_colors: bool

    def __init__(self, debug: bool = False, no_colors=None):
        self._debug = debug

        if no_colors is not None:
            self._no_colors = no_colors
        else:
            if platform.system() == "Windows":
                self._no_colors = False
            else:
                self._no_colors = True

    @property
    def debug(self) -> bool:
        """
        Get the debug mode.

        Returns:
            bool: The current debug mode value.
        """
        return self._debug

    @debug.setter
    def debug(self, value: bool):
        """
        Set the debug mode.

        Args:
            value (bool): The new debug mode value.

        Raises:
            ValueError: If the provided value is not a boolean.
        """
        if isinstance(value, bool):
            self._debug = value
        else:
            raise ValueError("Debug must be a boolean value")

    @property
    def no_colors(self) -> bool:
        """
        Get the colored output preference.

        Returns:
            bool: The current colored output preference value.
        """
        return self._no_colors

    @no_colors.setter
    def no_colors(self, value: bool):
        """
        Set the colored output preference.

        Args:
            value (bool): The new colored output preference value.

        Raises:
            ValueError: If the provided value is not a boolean.
        """
        if isinstance(value, bool):
            self._no_colors = value
        else:
            raise ValueError("Colored output must be a boolean value")
