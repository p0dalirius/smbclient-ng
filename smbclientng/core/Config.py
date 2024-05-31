#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Config.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 may 2024

import platform


class Config(object):
    def __init__(self, debug=False, no_colors=None):
        self._debug = debug

        if no_colors is not None:
            self._no_colors = no_colors
        else:
            if platform.system() == "Windows":
                self._no_colors = False
            else:
                self._no_colors = True

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, value):
        if isinstance(value, bool):
            self._debug = value
        else:
            raise ValueError("Debug must be a boolean value")

    @property
    def no_colors(self):
        return self._no_colors

    @no_colors.setter
    def no_colors(self, value):
        if isinstance(value, bool):
            self._no_colors = value
        else:
            raise ValueError("Colored output must be a boolean value")
