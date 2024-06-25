#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 may 2024

import argparse
import sys
from smbclientng.core.Config import Config
from smbclientng.core.Credentials import Credentials
from smbclientng.core.InteractiveShell import InteractiveShell
from smbclientng.core.Logger import Logger
from smbclientng.core.SessionsManager import SessionsManager


VERSION = "2.0"


def parseArgs():
    print(r"""               _          _ _            _                    
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _ 
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                         %10s  |___/  
    """ % ("v"+VERSION))

    parser = argparse.ArgumentParser(add_help=True, description="smbclient-ng, a fast and user friendly way to interact with SMB shares.")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    parser.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="No colors mode.")
    parser.add_argument("-S", "--startup-script", metavar="startup_script", required=False, type=str, help="File containing the list of commands to be typed at start of the console.")  
    parser.add_argument("-N", "--not-interactive", dest="not_interactive", required=False, action="store_true", default=False, help="Non interactive mode.")

    group_target = parser.add_argument_group("Target")
    group_target.add_argument("--host", action="store", metavar="HOST", required=True, type=str, help="IP address or hostname of the SMB Server to connect to.")  
    group_target.add_argument("--port", action="store", metavar="PORT", type=int, default=445, help="Port of the SMB Server to connect to. (default: 445)")

    authconn = parser.add_argument_group("Authentication & connection")
    authconn.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.")
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", default='.', help="(FQDN) domain to authenticate to.")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="User to authenticate with.")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k).")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", nargs="?", help="Password to authenticate with.")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="NT/LM hashes, format is LMhash:NThash.")
    cred.add_argument("--aes-key", dest="aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits).")
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.not_interactive and options.startup_script is None:
        print("[+] Option --not-interactive without --startup-script does not make any sense.")
        parser.print_help()
        sys.exit(1)

    if options.auth_username is not None and (options.auth_password is None and options.no_pass == False and options.auth_hashes is None):
        print("[+] No password or hashes provided and --no-pass is '%s'" % options.no_pass)
        from getpass import getpass
        if options.auth_domain is not None:
            options.auth_password = getpass("  | Provide a password for '%s\\%s':" % (options.auth_domain, options.auth_username))
        else:
            options.auth_password = getpass("  | Provide a password for '%s':" % options.auth_username)

    # Use AES Authentication key if available
    if options.aesKey is not None:
        options.use_kerberos = True
    if options.use_kerberos is True and options.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()
    
    # Parse hashes
    if options.auth_hashes is not None:
        if ":" not in options.auth_hashes:
            options.auth_hashes = ":" + options.auth_hashes

    return options


def main():
    """
    Main function to execute the smbclient-ng tool.

    This function handles the command-line arguments, initializes the SMB session,
    and starts the interactive shell. It also manages the authentication process
    using either password or hashes, and sets up the session configuration based
    on the provided command-line options.

    If Kerberos authentication is specified, it ensures that the KDC host is provided.
    It exits with an error message if necessary conditions are not met for the session
    to start properly.

    The function also handles debug mode outputs and exits cleanly, providing feedback
    about the session termination if debug mode is enabled.
    """

    options = parseArgs()

    config = Config()
    config.debug = options.debug
    config.no_colors = options.no_colors
    config.not_interactive = options.not_interactive
    config.startup_script = options.startup_script

    logger = Logger(config=config, logfile=None)

    sessionsManager = SessionsManager(config=config, logger=logger)

    if any([(options.auth_domain != '.'), (options.auth_username is not None), (options.auth_password is not None),(options.auth_hashes is not None)]):
        credentials = Credentials(
            domain=options.auth_domain,
            username=options.auth_username,
            password=options.auth_password,
            hashes=options.auth_hashes,
            use_kerberos=options.use_kerberos,
            aesKey=options.aesKey,
            kdcHost=options.kdcHost
        )
        sessionsManager.create_new_session(
            credentials=credentials,
            host=options.host,
            port=options.port
        )

    # Start the main interactive command line
    shell = InteractiveShell(
        sessionsManager=sessionsManager, 
        config=config,
        logger=logger
    )
    shell.run()

    if options.debug:
        print("[debug] Exiting the console.")


if __name__ == "__main__":
    main()
