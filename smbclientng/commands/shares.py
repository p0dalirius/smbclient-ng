#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : shares.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

from rich.console import Console
from rich.table import Table

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils.decorator import active_smb_connection_needed


class Command_shares(Command):
    name = "shares"
    description = "Lists the SMB shares served by the remote machine."

    HELP = {
        "description": [description, "Syntax: 'shares'"],
        "subcommands": ["rights"],
        "autocomplete": [],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument(
            "-R", "--rights", action="store_true", help="Check the rights of the shares"
        )
        return parser

    @active_smb_connection_needed
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : No
        # Active SMB connection needed : Yes
        # SMB share needed             : No

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        shares = interactive_shell.sessionsManager.current_session.list_shares()
        if len(shares.keys()) != 0:
            table = Table(title=None)
            table.add_column("Share")
            table.add_column("Visibility")
            table.add_column("Type")
            table.add_column("Description", justify="left")
            if self.options.rights:
                table.add_column("Rights")

            security_descriptor = list(shares.values())[0].get("security_descriptor")
            if security_descriptor is not None:
                table.add_column("Security Descriptor")

            for sharename in sorted(shares.keys()):
                types = ", ".join(
                    [s.replace("STYPE_", "") for s in shares[sharename]["type"]]
                )

                is_hidden = bool(sharename.endswith("$"))
                if is_hidden:
                    str_hidden = "[bold bright_blue]Hidden[/bold bright_blue]"
                    str_sharename = (
                        "[bold bright_blue]"
                        + shares[sharename]["name"]
                        + "[/bold bright_blue]"
                    )
                    str_types = "[bold bright_blue]" + types + "[/bold bright_blue]"
                    str_comment = (
                        "[bold bright_blue]"
                        + shares[sharename]["comment"]
                        + "[/bold bright_blue]"
                    )
                else:
                    str_hidden = "[bold bright_yellow]Visible[/bold bright_yellow]"
                    str_sharename = (
                        "[bold bright_yellow]"
                        + shares[sharename]["name"]
                        + "[/bold bright_yellow]"
                    )
                    str_types = "[bold bright_yellow]" + types + "[/bold bright_yellow]"
                    str_comment = (
                        "[bold bright_yellow]"
                        + shares[sharename]["comment"]
                        + "[/bold bright_yellow]"
                    )

                if self.options.rights:
                    try:
                        access_rights = interactive_shell.sessionsManager.current_session.test_rights(
                            sharename=shares[sharename]["name"], test_write=False
                        )
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
                    except Exception:
                        str_access_rights = ""

                if security_descriptor is not None:
                    sd_table = interactive_shell.sessionsManager.current_session.securityDescriptorTable(
                        b"".join(shares[sharename].get("security_descriptor")),
                        "sharename",
                        prefix="",
                        table_colors=True,
                    )

                if self.options.rights:
                    if security_descriptor is not None:
                        table.add_row(
                            str_sharename,
                            str_hidden,
                            str_types,
                            str_comment,
                            str_access_rights,
                            sd_table,
                        )
                    else:
                        table.add_row(
                            str_sharename,
                            str_hidden,
                            str_types,
                            str_comment,
                            str_access_rights,
                        )
                else:
                    if security_descriptor is not None:
                        table.add_row(
                            str_sharename, str_hidden, str_types, str_comment, sd_table
                        )
                    else:
                        table.add_row(str_sharename, str_hidden, str_types, str_comment)

            Console().print(table)
        else:
            interactive_shell.logger.error(
                "No share served on '%s'"
                % interactive_shell.sessionsManager.current_session.host
            )
