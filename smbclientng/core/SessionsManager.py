#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SessionsManager.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 may 2024

import datetime
from smbclientng.core.Credentials import Credentials
from smbclientng.core.ModuleArgumentParser import ModuleArgumentParser
from smbclientng.core.SMBSession import SMBSession
import time


class SessionsManager(object):
    """
    A class to manage SMB sessions.

    This class is responsible for creating, managing, and switching between multiple SMB sessions. It allows for the creation of new sessions with specified credentials and hosts, and provides methods to switch between existing sessions. It also keeps track of the current session and its ID.

    Attributes:
        next_session_id (int): The next available session ID.
        current_session (SMBSession): The currently active SMB session.
        current_session_id (int): The ID of the currently active session.
        sessions (dict): A dictionary of all active sessions, keyed by their session ID.
    """

    next_session_id = 1
    current_session = None
    current_session_id = None
    sessions = {}

    def __init__(self, config, logger):
        self.sessions = {}
        self.next_session_id = 1
        self.current_session = None
        self.current_session_id = None

        self.config = config
        self.logger = logger

    def create_new_session(self, credentials, host, port=445):
        """
        Creates a new session with the given session information.

        Args:
            session_info (dict): Information necessary to start a new session.

        Returns:
            None
        """
        
        smbSession = SMBSession(
            host=host,
            port=port,
            credentials=credentials,
            config=self.config,
            logger=self.logger
        )
        smbSession.init_smb_session()
        
        self.sessions[self.next_session_id] = {
            "id": self.next_session_id,
            "smbSession": smbSession,
            "created_at": int(time.time()),
        }
        self.switch_session(self.next_session_id)
        self.next_session_id += 1

    def switch_session(self, session_id):
        """
        Switches the current session to the session with the specified ID.

        Args:
            session_id (int): The ID of the session to switch to.

        Returns:
            bool: True if the session was successfully switched, False otherwise.
        """

        if session_id in self.sessions.keys():
            self.current_session = self.sessions[session_id]["smbSession"]
            self.current_session_id = session_id
            return True
        else:
            return False

    def delete_session(self, session_id):
        """
        Deletes a session with the given session ID.

        Args:
            session_id (int): The ID of the session to delete.

        Returns:
            bool: True if the session was successfully deleted, False otherwise.
        """

        if session_id in self.sessions.keys():
            self.sessions[session_id]["smbSession"].close_smb_session()
            del self.sessions[session_id]
            if self.current_session_id == session_id:
                self.current_session = None
                self.current_session_id = None
            return True
        return False

    def process_command_line(self, arguments):
        """
        Processes command line arguments to manage SMB sessions.

        This function parses the command line arguments provided to the application and determines the appropriate action to take,
        such as creating, interacting, deleting, or listing SMB sessions, or executing a command in one or more sessions.

        Args:
            arguments (list of str): The command line arguments.

        Returns:
            None
        """

        parser = ModuleArgumentParser(add_help=True, prog="sessions", description="")

        # interact
        mode_interact = ModuleArgumentParser(add_help=False, description="Switch to the specified session.")
        mode_interact.add_argument("-i", "--session-id", type=int, default=None, required=True, help="Session ID to interact with.")

        # Create
        mode_create = ModuleArgumentParser(add_help=False, description="Create a new session.")
        group_target = mode_create.add_argument_group("Target")
        group_target.add_argument("--host", action="store", metavar="HOST", required=True, type=str, help="IP address or hostname of the SMB Server to connect to.")  
        group_target.add_argument("--port", action="store", metavar="PORT", type=int, default=445, help="Port of the SMB Server to connect to. (default: 445)")
        authconn = mode_create.add_argument_group("Authentication & connection")
        authconn.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.")
        authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", default='.', help="(FQDN) domain to authenticate to.")
        authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="User to authenticate with.")
        secret = mode_create.add_argument_group()
        cred = secret.add_mutually_exclusive_group()
        cred.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k).")
        cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", nargs="?", help="Password to authenticate with.")
        cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="NT/LM hashes, format is LMhash:NThash.")
        cred.add_argument("--aes-key", dest="aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits).")
        secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line.")

        # Delete
        mode_delete = ModuleArgumentParser(add_help=False, description="Delete the specified session.")
        group_sessions = mode_delete.add_mutually_exclusive_group(required=True)
        group_sessions.add_argument("-i", "--session-id", type=int, default=[], action="append", help="One or more ID of sessions to target.")
        group_sessions.add_argument("-a", "--all", default=False, action="store_true", help="Delete all sessions.")

        # Execute
        mode_execute = ModuleArgumentParser(add_help=False, description="Send a smbclient-ng command line in one or more sessions.")
        group_sessions = mode_execute.add_mutually_exclusive_group(required=True)
        group_sessions.add_argument("-i", "--session-id", type=int, default=[], action="append", help="One or more ID of sessions to target.")
        group_sessions.add_argument("-a", "--all", default=False, action="store_true", help="Execute command in all sessions.")
        mode_execute.add_argument("-c", "--command", type=str, required=True, help="Command to execute in the target sessions.")

        # List
        mode_list = ModuleArgumentParser(add_help=False, description="List the registered sessions.")

        # Register subparsers
        subparsers = parser.add_subparsers(help="Action", dest="action", required=True)
        subparsers.add_parser("interact", parents=[mode_interact], help=mode_interact.description)
        subparsers.add_parser("create", parents=[mode_create], help=mode_create.description)
        subparsers.add_parser("delete", parents=[mode_delete], help=mode_delete.description)
        subparsers.add_parser("execute", parents=[mode_execute], help=mode_execute.description)
        subparsers.add_parser("list", parents=[mode_list], help=mode_list.description)

        try:
            options = parser.parse_args(arguments)
        except SystemExit as e:
            pass
        
        # Process actions

        # 
        if options.action == "interact":
            if options.session_id is not None:
                if options.session_id in self.sessions.keys():
                    self.logger.info("Switching to session #%d" % options.session_id)
                    self.switch_session(session_id=options.session_id)
                else:
                    self.logger.error("No session with id #%d" % options.session_id)

        # 
        elif options.action == "create":
            credentials = Credentials(
                domain=options.auth_domain,
                username=options.auth_username,
                password=options.auth_password,
                hashes=options.auth_hashes,
                use_kerberos=options.use_kerberos,
                aesKey=options.aesKey,
                kdcHost=options.kdcHost
            )
            self.create_new_session(
                credentials=credentials,
                host=options.host,
                port=options.port
            )
        
        # 
        elif options.action == "delete":
            if len(options.session_id) != 0:
                for session_id in options.session_id:
                    if session_id in self.sessions.keys():
                        self.logger.info("Closing and deleting session #%d" % session_id)
                        self.delete_session(session_id=session_id)
                    else:
                        self.logger.error("No session with id #%d" % session_id)
            elif options.all == True:
                all_session_ids = list(self.sessions.keys())
                for session_id in all_session_ids:
                    print("[+] Closing and deleting session #%d" % session_id)
                    self.delete_session(session_id=session_id)

        # 
        elif options.action == "execute":
            if options.command is not None:
                if len(options.session_id) != 0:
                    for session_id in session_id:
                        if session_id in self.sessions.keys():
                            self.logger.info("Executing '%s to session #%d" % (options.command, options.session_id))
                        else:
                            self.logger.error("No session with id #%d" % options.session_id)
                elif options.all == True:
                    all_session_ids = list(self.sessions.keys())
                    for session_id in all_session_ids:
                        pass
        
        # 
        elif options.action == "list":
            for sessionId in sorted(self.sessions.keys()):
                session = self.sessions[sessionId]["smbSession"]
                created_at_str = str(datetime.datetime.fromtimestamp(self.sessions[sessionId]["created_at"]))
                if sessionId == self.current_session_id:
                    if self.config.no_colors:
                        print(f"=> [#{sessionId:<2} - '{session.credentials.domain}\\{session.credentials.username}' @ {session.host}:{session.port}] created at [{created_at_str}] [current session]")
                    else:
                        print(f"\x1b[48;2;50;50;50m=> #{sessionId:<2} - '\x1b[1;96m{session.credentials.domain}\x1b[0m\x1b[48;2;50;50;50m\\\x1b[1;96m{session.credentials.username}\x1b[0m\x1b[48;2;50;50;50m\x1b[1m' @ {session.host}:{session.port} created at [{created_at_str}]\x1b[0m\x1b[48;2;50;50;50m [\x1b[93mcurrent session\x1b[0m\x1b[48;2;50;50;50m]\x1b[0m")
                else:
                    print(f"── #{sessionId:<2} - '\x1b[1;96m{session.credentials.domain}\x1b[0m\\\x1b[1;96m{session.credentials.username}\x1b[0m\x1b[1m' @ {session.host}:{session.port} created at [{created_at_str}]\x1b[0m")
                