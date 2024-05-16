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
import traceback
import impacket
from impacket.smbconnection import SMBConnection as impacketSMBConnection


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
            "dir": {
                "description": ["List the contents of the current working directory."], 
                "subcommands": []
            },
            "exit": {
                "description": ["Exits the smbclient-ng script."], 
                "subcommands": []
            },
            "help": {
                "description": ["Displays this help message."], 
                "subcommands": ["format"]
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
                            print(self.smbSession.list_contents().keys())
                            folder_contents = list(self.smbSession.list_contents().keys())
                            print(folder_contents)
                            folder_contents = folder_contents.remove('.')
                            folder_contents = folder_contents.remove('..')
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
        elif command == "reconnect":
            self.smbSession.init_smb_session()

        # List shares
        elif command == "shares":
            shares = self.smbSession.list_shares()
            if len(shares.keys()) != 0:
                max_sharename_len = max([len(sharename) for sharename, sharedata in shares.items()]) + 1

                for sharename in sorted(shares.keys()):
                    print("- \x1b[1;93m%s\x1b[0m | %s" % (sharename.ljust(max_sharename_len), shares[sharename]["comment"]))
            else:
                print("[!] No share served on '%s'" % self.smbSession.address)

        # Use a share
        elif command == "use":
            sharename = arguments[0]

            # Reload the list of shares
            self.smbSession.list_shares()

            if sharename in self.smbSession.shares.keys():
                self.smb_share = sharename
            else:
                print("[!] No share named '%s' on '%s'" % (sharename, self.smbSession.address))

        # Change directory to a share
        elif command == "cd":
            path = ' '.join(arguments).replace('/',r'\\')
            path = path + r'\\'
            path = re.sub(r'\\+', r'\\', path)

            if not path.startswith(r'\\'):
                # Relative path
                path = self.smb_path + path
            
            try:
                self.smbSession.list_contents(shareName=self.smb_share, path=path)
                self.smb_path = path
            except impacket.smbconnection.SessionError as e:
                print("[!] SMB Error: %s" % e)

        # Change directory to a share
        elif command == "ls" or command == "dir":
            # Reload the list of shares
            folder_contents = self.smbSession.list_contents(shareName=self.smb_share, path=self.smb_path)

            for longname in sorted(folder_contents.keys(), key=lambda x:x.lower()):
                entry = folder_contents[longname]

                meta_string = ""
                meta_string += ("d" if entry.is_directory() else "-" )
                meta_string += ("a" if entry.is_archive() else "-" )
                meta_string += ("c" if entry.is_compressed() else "-" )
                meta_string += ("h" if entry.is_hidden() else "-" )
                meta_string += ("n" if entry.is_normal() else "-" )
                meta_string += ("r" if entry.is_readonly() else "-" )
                meta_string += ("s" if entry.is_system() else "-" )
                meta_string += ("t" if entry.is_temporary() else "-" )

                size_str = b_filesize(entry.get_filesize())

                date_str = datetime.datetime.fromtimestamp(entry.get_atime_epoch()).strftime("%Y-%m-%d %H:%M")
                
                if entry.is_directory():
                    print("%s %10s  %s  \x1b[1;96m%s\x1b[0m\\" % (meta_string, size_str, date_str, longname))
                else:
                    print("%s %10s  %s  \x1b[1m%s\x1b[0m" % (meta_string, size_str, date_str, longname))

        else:
            pass

    def __prompt(self):

        if self.smb_share is None:
            str_prompt = "[\x1b[1;94m\\\\%s\\\x1b[0m]> " % (self.smbSession.address)

        else:
            str_path = "\\\\%s\\%s\\%s" % (self.smbSession.address, self.smb_share, self.smb_path)
            str_prompt = "[\x1b[1;94m%s\x1b[0m]> " % str_path

        return str_prompt


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

    def list_shares(self):
        resp = self.smbClient.listShares()

        self.shares = {}
        for share in resp:
            # SHARE_INFO_1 structure (lmshare.h)
            # https://docs.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_1
            sharename = share["shi1_netname"][:-1]
            sharecomment = share["shi1_remark"][:-1]
            sharetype = share["shi1_type"]

            self.shares[sharename] = {"name": sharename, "type": sharetype, "comment": sharecomment}
        
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