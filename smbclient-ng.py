#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ldapsearch.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jul 2021

import argparse
import datetime
import ntpath
import os
import readline
from sectools.windows.crypto import parse_lm_nt_hashes
import re
import sys
import time
import traceback
import impacket
from impacket.smbconnection import SMBConnection as impacketSMBConnection
from rich.progress import BarColumn, DownloadColumn, Progress, TaskID, TextColumn, TimeRemainingColumn, TransferSpeedColumn
from rich.console import Console
from rich.table import Table


VERSION = "2.1.0"


class CommandCompleter(object):
    """
    Class for handling command completion
    """
    def __init__(self, smbSession):
        self.smbSession = smbSession
        self.commands = {
            "cd": {
                "description": ["Change the current working directory."], 
                "subcommands": []
            },
            "close": {
                "description": ["Closes the SMB connection to the remote machine."], 
                "subcommands": []
            },
            "dir": {
                "description": ["List the contents of the current working directory."], 
                "subcommands": []
            },
            "exit": {
                "description": ["Exits the smbclient-ng script."], 
                "subcommands": []
            },
            "get": {
                "description": ["Get a remote file."], 
                "subcommands": []
            },
            "help": {
                "description": ["Displays this help message."], 
                "subcommands": ["format"]
            },
            "info": {
                "description": ["Get information about the server and or the share."], 
                "subcommands": ["server", "share"]
            },
            "lcd": {
                "description": ["Changes the current local directory."], 
                "subcommands": []
            },
            "lls": {
                "description": ["Changes the current local directory."], 
                "subcommands": []
            },
            "lmkdir": {
                "description": [""], 
                "subcommands": []
            },
            "lpwd": {
                "description": ["Shows the current local directory."], 
                "subcommands": []
            },
            "ls": {
                "description": ["List the contents of the current working directory."], 
                "subcommands": []
            },
            "reconnect": {
                "description": ["Reconnect to the remote machine (useful if connection timed out)."], 
                "subcommands": []
            },
            "shares": {
                "description": ["Lists the SMB shares served by the remote machine."], 
                "subcommands": []
            },
            "use": {
                "description": ["Use a SMB share.", "Syntax: use <sharename>"], 
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
                            # Choose folder
                            folder_contents = list(self.smbSession.list_contents().keys())
                            self.matches = [command + " " + s for s in folder_contents if s and s.startswith(remainder)]
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


def b_filesize(l):
    units = ['B','kB','MB','GB','TB','PB']
    for k in range(len(units)):
        if l < (1024**(k+1)):
            break
    return "%4.2f %s" % (round(l/(1024**(k)),2), units[k])


class InteractiveShell(object):

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
        
        #
        elif command in ["reconnect", "connect"]:
            self.smbSession.init_smb_session()

        #
        elif command == "close":
            self.smbSession.close_smb_session()

        # List shares
        elif command == "shares":
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
                        table.add_row(
                            sharename,
                            str(is_hidden),
                            types,
                            shares[sharename]["comment"]
                        )
                    else:
                        table.add_row(
                            sharename,
                            str(is_hidden),
                            types,
                            shares[sharename]["comment"]
                        )

                console = Console()
                console.print(table)

                # max_sharename_len = max([len(sharename) for sharename, sharedata in shares.items()]) + 1

                # for sharename in sorted(shares.keys()):
                #     print("- \x1b[1;93m%s\x1b[0m | %s" % (sharename.ljust(max_sharename_len), shares[sharename]["comment"]))
            else:
                print("[!] No share served on '%s'" % self.smbSession.address)

        # Use a share
        elif command == "use":
            if len(arguments) != 0:
                sharename = arguments[0]

                # Reload the list of shares
                self.smbSession.list_shares()

                if sharename in self.smbSession.shares.keys():
                    self.smb_share = sharename
                    self.smbSession.smb_share = sharename
                else:
                    print("[!] No share named '%s' on '%s'" % (sharename, self.smbSession.address))
            else:
                self.commandCompleterObject.print_help(command=command)   

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

        # Changes the current local directory.
        elif command == "lcd":
            if len(arguments) != 0:
                path = ' '.join(arguments)
                if os.path.exists(path=path):
                    if os.path.isdir(s=path):
                        os.chdir(path=path)
                    else:
                        print("[!] Path '%s' is not a directory." % path)
                else:
                    print("[!] Folder '%s' does not exists." % path)
            else:
                self.commandCompleterObject.print_help(command=command)

        # 
        elif command == "lls":
            pass

        # 
        elif command == "lmkdir":
            path = ' '.join(arguments)
            if not os.path.exists(path):
                os.mkdir(path=path)

        # Shows the current local directory.
        elif command == "lpwd":
            # print("Current local working directory:")
            print(os.getcwd())

        # Change directory to a share
        elif command == "ls" or command == "dir":
            # 
            if self.smb_share is not None:
                # Read the files
                folder_contents = self.smbSession.list_contents(
                    shareName=self.smb_share, 
                    path=self.smb_path
                )

                for longname in sorted(folder_contents.keys(), key=lambda x:x.lower()):
                    entry = folder_contents[longname]

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

        # Get a file
        elif command == "get":
            if self.smb_share is not None:
                try:
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

                except KeyboardInterrupt as e:
                    print("[!] Interrupted.")
            else:
                print("[!] You must open a share first, try the 'use <share>' command.")

        # SMB server info
        elif command == "info":
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
            pass

    def __prompt(self):

        if self.smb_share is None:
            str_prompt = "[\x1b[1;94m\\\\%s\\\x1b[0m]> " % (self.smbSession.address)

        else:
            str_path = "\\\\%s\\%s\\%s" % (self.smbSession.address, self.smb_share, self.smb_path)
            str_prompt = "[\x1b[1;94m%s\x1b[0m]> " % str_path

        return str_prompt


def STYPE_MASK(stype_value):
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


class FileWriter(object):
    def __init__(self, path=None, expected_size=None, debug=False):
        super(FileWriter, self).__init__()

        self.path = path
        self.path = self.path.replace('\\', '/')

        self.dir = None
        if '/' in self.path:
            self.dir = os.path.dirname(self.path)
            if not os.path.exists(self.dir):
                os.makedirs(self.dir)

        self.debug = debug
        self.expected_size = expected_size

        if self.debug:
            print("[debug] Openning '%s'" % self.path)
        self.f = open(self.path, "wb")

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
        self.f.write(data)
    
    def close(self, remove=False):
        self.f.close()

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
    Documentation for class SMBSession
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

    def close_smb_session(self):
        print("[>] Closing the current SMB connection ...")
        self.smbClient.close()

    def list_shares(self):
        self.shares = {}
        
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
            print("")

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

    def get_file(self, path=None):
        matches = self.smbClient.listPath(shareName=self.smb_share, path=path)
        for entry in matches:
            if entry.is_directory():
                print("[>] Skipping '%s' because it is a directory." % path)
            else:
                f = FileWriter(path=entry.get_longname(), expected_size=entry.get_filesize())
                self.smbClient.getFile(
                    shareName=self.smb_share, 
                    pathName=entry.get_longname(), 
                    callback=f.write
                )
                f.close()
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
                        f = FileWriter(
                            path=remote_smb_path + '\\' + entry_file.get_longname(), 
                            expected_size=entry_file.get_filesize()
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
        recurse_action(
            base_dir=self.smb_path, 
            path=[path]
        )

    def put_file(self, path=None):
        pass

    def put_file_recursively(self, path=None):
        pass

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


def parseArgs():
    print("""               _          _ _            _                    
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _ 
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                         %10s  |___/  
    """ % ("v"+VERSION))

    parser = argparse.ArgumentParser(add_help=True, description="smbclient-ng")
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