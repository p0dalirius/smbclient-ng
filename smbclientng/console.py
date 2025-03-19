# Built-in imports
import argparse
import sys

# Local library imports
from smbclientng.core.Config import Config
from smbclientng.core.Credentials import Credentials
from smbclientng.core.InteractiveShell import InteractiveShell
from smbclientng.core.Logger import Logger
from smbclientng.core.SessionsManager import SessionsManager


VERSION = "2.1.8"


def parse_args():
    """Parse command-line arguments."""
    print(
        r"""               _          _ _            _
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                         %10s  |___/
    """
        % ("v" + VERSION)
    )

    parser = argparse.ArgumentParser(
        description="smbclient-ng, a fast and user-friendly way to interact with SMB shares."
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode.")
    parser.add_argument(
        "--no-colors", action="store_true", help="Disable colored output."
    )
    parser.add_argument(
        "-S", "--startup-script", type=str, help="Startup script with commands."
    )
    parser.add_argument(
        "-N", "--not-interactive", action="store_true", help="Non-interactive mode."
    )
    parser.add_argument("-L", "--logfile", type=str, help="Log file path.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=3,
        help="Timeout for SMB connections (default: 3s)",
    )
    parser.add_argument("--advertised-name", type=str, help="Advertised machine name.")

    # Target arguments
    target = parser.add_argument_group("Target")
    target.add_argument(
        "--host", required=True, type=str, help="SMB Server IP or hostname."
    )
    target.add_argument(
        "--port", type=int, default=445, help="SMB Server port (default: 445)."
    )

    # Authentication arguments
    auth = parser.add_argument_group("Authentication & Connection")
    auth.add_argument("--kdcHost", type=str, help="FQDN of KDC for Kerberos.")
    auth.add_argument(
        "-d", "--domain", default=".", type=str, help="Authentication domain."
    )
    auth.add_argument("-u", "--user", type=str, help="Username for authentication.")

    # Password & Hashes
    secret = parser.add_argument_group("Secrets")
    creds = secret.add_mutually_exclusive_group()
    creds.add_argument(
        "--no-pass", action="store_true", help="Do not prompt for a password."
    )
    creds.add_argument("-p", "--password", type=str, nargs="?", help="Password.")
    creds.add_argument(
        "-H", "--hashes", type=str, metavar="[LMHASH:]NTHASH", help="NT/LM hashes."
    )
    creds.add_argument(
        "--aes-key", type=str, metavar="HEXKEY", help="AES key for Kerberos auth."
    )
    secret.add_argument(
        "-k", "--kerberos", action="store_true", help="Use Kerberos authentication."
    )

    options = parser.parse_args()

    if options.not_interactive and options.startup_script is None:
        print("[+] Option --not-interactive requires --startup-script.")
        sys.exit(1)

    if options.user and not (options.password or options.no_pass or options.hashes):
        from getpass import getpass

        options.password = getpass(
            f"  | Provide a password for '{options.domain}\\{options.user}': "
        )

    if options.aes_key:
        options.kerberos = True

    if options.kerberos and not options.kdcHost:
        print("[!] Kerberos authentication requires --kdcHost.")
        sys.exit(1)

    if options.hashes and ":" not in options.hashes:
        options.hashes = ":" + options.hashes

    return options


def run():
    """Run the SMBClient-NG CLI."""
    options = parse_args()

    config = Config()
    config.debug = options.debug
    config.no_colors = options.no_colors
    config.not_interactive = options.not_interactive
    config.startup_script = options.startup_script

    logger = Logger(config=config, logfile=options.logfile)
    sessions_manager = SessionsManager(config=config, logger=logger)

    if any([options.domain != ".", options.user, options.password, options.hashes]):
        credentials = Credentials(
            domain=options.domain,
            username=options.user,
            password=options.password,
            hashes=options.hashes,
            use_kerberos=options.kerberos,
            aesKey=options.aes_key,
            kdcHost=options.kdcHost,
        )
        sessions_manager.create_new_session(
            credentials=credentials,
            host=options.host,
            port=options.port,
            timeout=options.timeout,
            advertisedName=options.advertised_name,
        )

    shell = InteractiveShell(
        sessionsManager=sessions_manager, config=config, logger=logger
    )
    shell.run()

    logger.debug("Exiting the console.")
