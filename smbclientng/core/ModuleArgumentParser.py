#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ModuleArgumentParser.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024


import argparse
import sys

class ModuleArgumentParser(argparse.ArgumentParser):

    def error(self, message):
        sys.stderr.write('[!] Error: %s\n' % message)
        self.print_help()
        #sys.exit(2)