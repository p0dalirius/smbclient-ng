#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 may 2024

import argparse
import sys
from smbclientng.core.Config import Config
from smbclientng.core.InteractiveShell import InteractiveShell
from smbclientng.core.SMBSession import SMBSession
from smbclientng.core.utils import parse_lm_nt_hashes


VERSION = "1.3.1"


def parseArgs():
    print("""               _          _ _            _                    
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _ 
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                         %10s  |___/  
    """ % ("v"+VERSION))

    parser = argparse.ArgumentParser(add_help=True, description="smbclient-ng, a fast and user friendly way to interact with SMB shares.")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    parser.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="No colors mode.")
    parser.add_argument("--target", action="store", metavar="ip address", required=True, type=str, help="IP Address of the SMB Server to connect to.")  

    authconn = parser.add_argument_group("Authentication & connection")
    authconn.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.")
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", default='.', help="(FQDN) domain to authenticate to")
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

    config = Config()
    config.debug = options.debug
    config.no_colors = options.no_colors

    smbSession = SMBSession(
        address=options.target,
        domain=options.auth_domain,
        username=options.auth_username,
        password=options.auth_password,
        lmhash=auth_lm_hash,
        nthash=auth_nt_hash,
        use_kerberos=options.use_kerberos,
        config=config
    )
    smbSession.init_smb_session()

    shell = InteractiveShell(
        smbSession=smbSession, 
        config=config
    )
    shell.run()

    if options.debug:
        print("[debug] Exiting the console.")

if __name__ == "__main__":
    main()