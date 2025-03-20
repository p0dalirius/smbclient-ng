#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : shares.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from smbclientng.utils.decorator import active_smb_connection_needed
from rich.console import Console
from rich.table import Table
from smbclientng.core.Command import Command


class Command_shares(Command):
    HELP = {
        "description": [
                "Lists the SMB shares served by the remote machine.", 
            "Syntax: 'shares'"
        ], 
        "subcommands": ["rights"],
        "autocomplete": []
    }

    @classmethod
    @active_smb_connection_needed
    def run(cls, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : No

        test_write = False
        do_check_rights = False
        if len(arguments) != 0:
            if arguments[0] == "rights":
                do_check_rights = True
                test_write = False

        if do_check_rights:
            interactive_shell.logger.print("WARNING: Checking WRITE access to shares in offensive tools implies creating a folder and trying to delete it.")
            interactive_shell.logger.print("| If you have CREATE_CHILD rights but no DELETE_CHILD rights, the folder cannot be deleted and will remain on the target.")
            interactive_shell.logger.print("| Do you want to continue? [N/y] ", end='')
            user_response = input()
            interactive_shell.logger.write_to_logfile(user_response)
            while user_response.lower().strip() not in ['y', 'n']:
                interactive_shell.logger.print("| Invalid response, Do you want to continue? [N/y] ", end='')
                user_response = input()
                interactive_shell.logger.write_to_logfile(user_response)
            if user_response.lower().strip() == 'y':
                test_write = True

        shares = interactive_shell.sessionsManager.current_session.list_shares()
        if len(shares.keys()) != 0:
            table = Table(title=None)
            table.add_column("Share")
            table.add_column("Visibility")
            table.add_column("Type")
            table.add_column("Description", justify="left")
            if do_check_rights:
                table.add_column("Rights")

            security_descriptor = list(shares.values())[0].get("security_descriptor")
            if security_descriptor is not None:
                table.add_column("Security Descriptor")

            for sharename in sorted(shares.keys()):
                types = ', '.join([s.replace("STYPE_","") for s in shares[sharename]["type"]])

                is_hidden = bool(sharename.endswith('$'))
                if is_hidden:
                    str_hidden = "[bold bright_blue]Hidden[/bold bright_blue]"
                    str_sharename = "[bold bright_blue]" + shares[sharename]["name"] + "[/bold bright_blue]"
                    str_types = "[bold bright_blue]" + types + "[/bold bright_blue]"
                    str_comment = "[bold bright_blue]" + shares[sharename]["comment"] + "[/bold bright_blue]"
                else:
                    str_hidden = "[bold bright_yellow]Visible[/bold bright_yellow]"
                    str_sharename = "[bold bright_yellow]" + shares[sharename]["name"] + "[/bold bright_yellow]"
                    str_types = "[bold bright_yellow]" + types + "[/bold bright_yellow]"
                    str_comment = "[bold bright_yellow]" + shares[sharename]["comment"] + "[/bold bright_yellow]"

                if do_check_rights:
                    try:
                        access_rights = interactive_shell.sessionsManager.current_session.test_rights(sharename=shares[sharename]["name"], test_write=test_write)
                        str_access_rights = "[bold yellow]NO ACCESS[/bold yellow]"
                        if access_rights["readable"] and access_rights["writable"]:
                            str_access_rights = "[bold green]READ[/bold green], [bold red]WRITE[/bold red]"
                        elif access_rights["readable"]:
                            str_access_rights = "[bold green]READ[/bold green]"
                        elif access_rights["writable"]:
                            # Without READ?? This should not happen IMHO
                            str_access_rights = "[bold red]WRITE[/bold red]"
                        else:
                            str_access_rights = "[bold yellow]NO ACCESS[/bold yellow]"
                    except:
                        str_access_rights = ""

                if security_descriptor is not None:
                    sd_table = interactive_shell.sessionsManager.current_session.securityDescriptorTable(b''.join(shares[sharename].get("security_descriptor")), "sharename", prefix="", table_colors=True)

                if do_check_rights:
                    if security_descriptor is not None:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment, str_access_rights, sd_table)
                    else:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment, str_access_rights)
                else:
                    if security_descriptor is not None:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment, sd_table)
                    else:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment)

            Console().print(table)
        else:
            interactive_shell.logger.error("No share served on '%s'" % interactive_shell.sessionsManager.current_session.host)