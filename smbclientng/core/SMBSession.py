#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SMBSession.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 mar 2025

from __future__ import annotations

import io
import ntpath
import os
import random
import re
import subprocess
import sys
import traceback
from typing import TYPE_CHECKING, Optional

from impacket.dcerpc.v5 import rpcrt, srvs, transport
from impacket.ldap import ldaptypes
from impacket.nt_errors import STATUS_OBJECT_NAME_COLLISION
from impacket.smb import SMBFileStreamInformation
from impacket.smb3structs import (DACL_SECURITY_INFORMATION,
                                  FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
                                  FILE_OPEN, FILE_READ_ATTRIBUTES,
                                  GROUP_SECURITY_INFORMATION,
                                  OWNER_SECURITY_INFORMATION, READ_CONTROL,
                                  SMB2_0_INFO_FILE, SMB2_FILE_STREAM_INFO)
from impacket.smbconnection import SessionError, SMBConnection

from smbclientng.core.LocalFileIO import LocalFileIO
from smbclientng.core.SIDResolver import SIDResolver
from smbclientng.utils.paths import normalize_alternate_data_stream_path
from smbclientng.utils.utils import (STYPE_MASK, filesize, is_port_open,
                                     smb_entry_iterator)

if TYPE_CHECKING:
    from impacket.smb import SharedFile

    from smbclientng.core.Logger import Logger
    from smbclientng.types.Config import Config
    from smbclientng.types.Credentials import Credentials


class SMBSession(object):
    """
    Represents an SMB session for interacting with an SMB server.

    This class provides methods to manage and interact with an SMB server, including
    connecting to the server, listing shares, uploading and downloading files, and
    managing directories and files on the server. It handles session initialization,
    authentication, and cleanup.

    Attributes:
        host (str): The hostname or IP address of the SMB server.
        port (int): The port number on which the SMB server is listening.
        credentials (dict): Authentication credentials for the SMB server.
        config (dict, optional): Configuration options for the SMB session.
        smbClient (impacket.smbconnection.SMBConnection): The SMB connection instance.
        connected (bool): Connection status to the SMB server.
        available_shares (dict): A dictionary of available SMB shares.
        smb_share (str): The current SMB share in use.
        smb_cwd (str): The current working directory on the SMB share.
        smb_tree_id (int): The tree ID of the connected SMB share.

    Methods:
        close_smb_session(): Closes the current SMB session.
        init_smb_session(): Initializes the SMB session with the server.
        list_shares(): Lists all shares available on the SMB server.
        set_share(shareName): Sets the current SMB share.
        set_cwd(path): Sets the current working directory on the SMB share.
        put_file(localpath): Uploads a file to the current SMB share.
        get_file(remotepath, localpath): Downloads a file from the SMB share.
        mkdir(path): Creates a directory on the SMB share.
        rmdir(path): Removes a directory from the SMB share.
        rm(path): Removes a file from the SMB share.
        read_file(path): Reads a file from the SMB share.
        test_rights(sharename): Tests read and write access rights on a share.
    """

    config: Config
    logger: Logger
    host: str
    port: int
    timeout: int
    advertisedName: Optional[str]

    # Credentials
    credentials: Credentials

    smbClient: Optional[SMBConnection] = None
    connected: bool = False

    available_shares: dict[str, dict] = {}
    smb_share: Optional[str] = None
    smb_cwd: str = ""
    smb_tree_id: Optional[int] = None

    dce_srvsvc: Optional[rpcrt.DCERPC_v5] = None
    sid_resolver: SIDResolver

    def __init__(
        self,
        host,
        port,
        timeout,
        credentials,
        advertisedName=None,
        config=None,
        logger=None,
    ):
        super(SMBSession, self).__init__()
        # Objects
        self.config = config
        self.logger = logger

        # Target server
        self.host = host
        # Target port (by default on 445)
        self.port = port
        # Timeout (default 3 seconds)
        self.timeout = timeout
        self.advertisedName = advertisedName

        # Credentials
        self.credentials = credentials

        self.list_shares()

    # Connect and disconnect SMB session

    def close_smb_session(self):
        """
        Closes the current SMB session by disconnecting the SMB client.

        This method ensures that the SMB client connection is properly closed. It checks if the client is connected
        and if so, it closes the connection and resets the connection status.

        Raises:
            Exception: If the SMB client is not initialized or if there's an error during the disconnection process.
        """

        if self.smbClient is not None:
            if self.connected:
                self.smbClient.close()
                self.connected = False
                self.logger.debug("[+] SMB connection closed successfully.")
            else:
                self.logger.debug("[!] No active SMB connection to close.")
        else:
            raise Exception("SMB client is not initialized.")

    def init_smb_session(self) -> bool:
        """
        Initializes and establishes a session with the SMB server.

        This method sets up the SMB connection using either Kerberos or NTLM authentication based on the configuration.
        It attempts to connect to the SMB server specified by the `address` attribute and authenticate using the credentials provided during the object's initialization.

        The method will print debug information if the `debug` attribute is set to True. Upon successful connection and authentication, it sets the `connected` attribute to True.

        Returns:
            bool: True if the connection and authentication are successful, False otherwise.
        """

        self.connected = False

        self.logger.debug("[>] Connecting to remote SMB server '%s' ... " % self.host)

        try:
            result, error = is_port_open(self.host, self.port, self.timeout)
            if result:
                self.smbClient = SMBConnection(
                    remoteName=self.host,
                    remoteHost=self.host,
                    myName=self.advertisedName,
                    sess_port=int(self.port),
                    timeout=self.timeout,
                )
                self.connected = True
            else:
                self.logger.error(
                    f"Could not connect to '{self.host}:{self.port}', {error}."
                )
                self.connected = False
                return False
        except OSError as err:
            if self.config.debug:
                traceback.print_exc()
            self.logger.error(
                "Could not connect to '%s:%d': %s" % (self.host, int(self.port), err)
            )
            self.connected = False
            return False

        if self.credentials.use_kerberos:
            self.logger.debug(
                "[>] Authenticating as '%s\\%s' with kerberos ... "
                % (self.credentials.domain, self.credentials.username)
            )
            # Set KRB5CCNAME environment variable if ccacheFile is provided
            original_krb5ccname = None
            if self.credentials.ccacheFile:
                original_krb5ccname = os.environ.get("KRB5CCNAME")
                os.environ["KRB5CCNAME"] = self.credentials.ccacheFile
                self.logger.debug(f"  | Using CCache file: {self.credentials.ccacheFile}")
            try:
                # When using CCache file, don't pass password/hashes to avoid TGT request
                # Let impacket use the tickets from the CCache file directly
                if self.credentials.ccacheFile:
                    self.connected = self.smbClient.kerberosLogin(
                        user=self.credentials.username,
                        password="",
                        domain=self.credentials.domain,
                        lmhash="",
                        nthash="",
                        aesKey=None,
                        kdcHost=self.credentials.kdcHost,
                        useCache=True,
                    )
                else:
                    self.connected = self.smbClient.kerberosLogin(
                        user=self.credentials.username,
                        password=self.credentials.password,
                        domain=self.credentials.domain,
                        lmhash=self.credentials.lm_hex,
                        nthash=self.credentials.nt_hex,
                        aesKey=self.credentials.aesKey,
                        kdcHost=self.credentials.kdcHost,
                        useCache=False,
                    )
            except SessionError as err:
                if self.config.debug:
                    traceback.print_exc()
                self.logger.error("Could not login: %s" % err)
                self.connected = False
            finally:
                # Restore original KRB5CCNAME if it was set
                if original_krb5ccname is not None:
                    os.environ["KRB5CCNAME"] = original_krb5ccname
                elif self.credentials.ccacheFile and "KRB5CCNAME" in os.environ:
                    del os.environ["KRB5CCNAME"]

        else:
            if len(self.credentials.lm_hex) != 0 and len(self.credentials.nt_hex) != 0:
                self.logger.debug(
                    "[>] Authenticating as '%s\\%s' with NTLM with pass the hash ... "
                    % (self.credentials.domain, self.credentials.username)
                )
                try:
                    self.logger.debug("  | user     = %s" % self.credentials.username)
                    self.logger.debug("  | password = %s" % self.credentials.password)
                    self.logger.debug("  | domain   = %s" % self.credentials.domain)
                    self.logger.debug("  | lmhash   = %s" % self.credentials.lm_hex)
                    self.logger.debug("  | nthash   = %s" % self.credentials.nt_hex)

                    self.connected = self.smbClient.login(
                        user=self.credentials.username,
                        password=self.credentials.password,
                        domain=self.credentials.domain,
                        lmhash=self.credentials.lm_hex,
                        nthash=self.credentials.nt_hex,
                    )
                except SessionError as err:
                    if self.config.debug:
                        traceback.print_exc()
                    self.logger.error("Could not login: %s" % err)
                    self.connected = False

            else:
                self.logger.debug(
                    "[>] Authenticating as '%s\\%s' with NTLM with password ... "
                    % (self.credentials.domain, self.credentials.username)
                )
                try:
                    self.logger.debug("  | user     = %s" % self.credentials.username)
                    self.logger.debug("  | password = %s" % self.credentials.password)
                    self.logger.debug("  | domain   = %s" % self.credentials.domain)
                    self.logger.debug("  | lmhash   = %s" % self.credentials.lm_hex)
                    self.logger.debug("  | nthash   = %s" % self.credentials.nt_hex)

                    self.connected = self.smbClient.login(
                        user=self.credentials.username,
                        password=self.credentials.password,
                        domain=self.credentials.domain,
                        lmhash=self.credentials.lm_hex,
                        nthash=self.credentials.nt_hex,
                    )
                except SessionError as err:
                    if self.config.debug:
                        traceback.print_exc()
                    self.logger.error("Could not login: %s" % err)
                    self.connected = False

        if self.connected:
            self.logger.print(
                "[+] Successfully authenticated to '%s' as '%s\\%s'!"
                % (self.host, self.credentials.domain, self.credentials.username)
            )
        else:
            self.logger.error(
                "Failed to authenticate to '%s' as '%s\\%s'!"
                % (self.host, self.credentials.domain, self.credentials.username)
            )

        if self.connected:
            try:
                self.sid_resolver = SIDResolver(self.smbClient)
            except Exception as err:
                self.logger.error(f"SIDResolver could not be initialized: {err}")
            try:
                rpctransport = transport.SMBTransport(
                    self.smbClient.getRemoteName(),
                    self.smbClient.getRemoteHost(),
                    filename=r"\srvsvc",
                    smb_connection=self.smbClient,
                )
                self.dce_srvsvc = rpctransport.get_dce_rpc()
                self.dce_srvsvc.connect()
                self.dce_srvsvc.bind(srvs.MSRPC_UUID_SRVS)
            except Exception as err:
                self.logger.error(f"Could not initialize connection to srvsvc: {err}")

        return self.connected

    def ping_smb_session(self) -> bool:
        """
        Tests the connectivity to the SMB server by sending an echo command.

        This method attempts to send an echo command to the SMB server to check if the session is still active.
        It updates the `connected` attribute of the class based on the success or failure of the echo command.

        Returns:
            bool: True if the echo command succeeds (indicating the session is active), False otherwise.
        """

        portIsOpen, error = is_port_open(self.host, self.port, self.timeout)
        if not portIsOpen:
            self.connected = False
        else:
            try:
                # Try to ping the SMB server to see if we timed out
                self.smbClient.getSMBServer().echo()
            except Exception:
                self.connected = False

        return self.connected

    # Operations
    def get_file(
        self,
        path: Optional[str] = None,
        keepRemotePath: bool = False,
        localDownloadDir: str = "./",
        is_recursive: bool = False,
    ):
        """
        Retrieves files or directories from the specified path(s) on the SMB share.

        This method attempts to retrieve a file from the given path within the currently connected SMB share.
        If the path points to a directory, it skips the retrieval. It handles file retrieval by creating a local
        file object and writing the contents of the remote file to it using the SMB client's getFile method.

        Parameters:
            path (str): The path of the file, directory, or pattern to retrieve.
            keepRemotePath (bool): Whether to preserve the remote directory structure locally.
            localDownloadDir (str): The local directory to download files into.

        Returns:
            None
        """
        if path is None:
            path = self.smb_cwd or ""

        # Normalize and parse the path
        path = path.replace("/", ntpath.sep)
        path = ntpath.normpath(path)

        # Handle paths starting with './' or '.\'
        if path.startswith("." + ntpath.sep) or path.startswith("." + os.path.sep):
            # Remove the './' or '.\' prefix
            path = path[2:]
            path = ntpath.normpath(ntpath.join(self.smb_cwd or "", path))
        elif not ntpath.isabs(path):
            # Relative path
            path = ntpath.normpath(ntpath.join(self.smb_cwd or "", path))
        else:
            # Absolute path (remove leading backslash)
            path = path.lstrip(ntpath.sep)
            path = ntpath.normpath(path)

        if self.path_isdir(path):
            # Handle directories
            max_depth = None if is_recursive else 0
            start_paths = [path]

            generator = smb_entry_iterator(
                smb_client=self.smbClient,
                smb_share=self.smb_share,
                start_paths=start_paths,
                exclusion_rules=[],
                max_depth=max_depth,
            )

            entry_count = 0
            fullpath = None
            for entry, fullpath, depth, is_last_entry in generator:
                entry_count += 1
                try:
                    if entry.is_directory():
                        if keepRemotePath:
                            base_path = "./"  # Use root as base
                            relative_path = ntpath.relpath(fullpath, base_path)
                            relative_path = relative_path.replace(
                                ntpath.sep, os.path.sep
                            )
                            output_path = os.path.normpath(
                                os.path.join(localDownloadDir, relative_path)
                            )
                            os.makedirs(output_path, exist_ok=True)
                            self.logger.info(f"Created directory: {output_path}")
                        else:
                            # Do not create directories when keepRemotePath is False
                            pass
                    else:
                        if keepRemotePath:
                            base_path = "./"  # Use root as base
                            relative_path = ntpath.relpath(fullpath, base_path)
                            relative_path = relative_path.replace(
                                ntpath.sep, os.path.sep
                            )
                            output_path = os.path.normpath(
                                os.path.join(localDownloadDir, relative_path)
                            )
                        else:
                            relative_path = ntpath.basename(fullpath)
                            output_path = os.path.normpath(
                                os.path.join(localDownloadDir, relative_path)
                            )

                        # Ensure the parent directory exists
                        output_dir = os.path.dirname(output_path)
                        if output_dir and not os.path.exists(output_dir):
                            os.makedirs(output_dir, exist_ok=True)

                        self.download_file(fullpath, output_path, keepRemotePath)
                except Exception as e:
                    self.logger.error(f"Failed to process '{fullpath}': {e}")

            self.logger.info(
                f"Total entries processed in the directory '{fullpath}': {entry_count}"
            )
        else:
            # Handle files
            try:
                entry_name = ntpath.basename(path)
                if not entry_name:
                    self.logger.error(
                        f"Cannot determine the file name from the path: '{path}'"
                    )
                    return
                if keepRemotePath:
                    base_path = "./"  # Use root as base
                    relative_path = ntpath.relpath(path, base_path)
                    relative_path = relative_path.replace(ntpath.sep, os.path.sep)
                    output_filepath = os.path.normpath(
                        os.path.join(localDownloadDir, relative_path)
                    )
                else:
                    relative_path = entry_name
                    output_filepath = os.path.normpath(
                        os.path.join(localDownloadDir, relative_path)
                    )

                # Ensure the parent directory exists
                output_dir = os.path.dirname(output_filepath)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)

                self.download_file(path, output_filepath, keepRemotePath)
            except Exception as e:
                self.logger.error(f"Failed to download '{path}': {e}")

    def download_file(self, full_path: str, outputfile: str, keepRemotePath: bool):
        """Downloads a single file."""
        try:
            # Get the file entry
            entries = self.smbClient.listPath(self.smb_share, full_path)
            # Ensure no directory will be processed
            entries = [e for e in entries if e.get_longname() not in [".", ".."]]
            if len(entries) == 1 and not entries[0].is_directory():
                entry = entries[0]
                # Download the file
                f = LocalFileIO(
                    mode="wb",
                    path=outputfile,
                    logger=self.logger,
                    expected_size=entry.get_filesize(),
                    keepRemotePath=keepRemotePath,
                )
                try:
                    self.smbClient.getFile(
                        shareName=self.smb_share, pathName=full_path, callback=f.write
                    )
                finally:
                    f.close()
        except Exception as e:
            self.logger.error(f"Failed to download '{full_path}': {e}")

    def get_file_recursively(
        self, path: Optional[str] = None, localDownloadDir: str = "./"
    ):
        """
        Recursively retrieves files from a specified path on the SMB share.

        This method navigates through all directories starting from the given path,
        and downloads all files found. It handles directories recursively, ensuring
        that all nested files are retrieved. The method skips over directory entries
        and handles errors gracefully, attempting to continue the operation where possible.

        Parameters:
            path (str): The initial directory path from which to start the recursive file retrieval.
                        If None, it starts from the root of the configured SMB share.
        """

        def recurse_action(base_dir="", path=[], localDownloadDir="./"):
            if len(base_dir) == 0:
                remote_smb_fullpath = ntpath.sep.join(path)
            else:
                remote_smb_fullpath = base_dir + ntpath.sep + ntpath.sep.join(path)
            remote_smb_fullpath = ntpath.normpath(remote_smb_fullpath)

            remote_smb_relativepath = ntpath.normpath(ntpath.sep.join(path))

            entries = self.smbClient.listPath(
                shareName=self.smb_share, path=remote_smb_fullpath + ntpath.sep + "*"
            )
            if len(entries) != 0:
                files = [entry for entry in entries if not entry.is_directory()]
                directories = [
                    entry
                    for entry in entries
                    if entry.is_directory() and entry.get_longname() not in [".", ".."]
                ]

                # Files
                if len(files) != 0:
                    self.logger.print(
                        "[>] Retrieving files of '%s'" % remote_smb_relativepath
                    )
                for entry_file in files:
                    if not entry_file.is_directory():
                        downloadToPath = (
                            localDownloadDir
                            + os.path.sep
                            + remote_smb_relativepath
                            + os.path.sep
                            + entry_file.get_longname()
                        )
                        f = LocalFileIO(
                            mode="wb",
                            path=downloadToPath,
                            logger=self.logger,
                            expected_size=entry_file.get_filesize(),
                            keepRemotePath=True,
                        )
                        try:
                            self.smbClient.getFile(
                                shareName=self.smb_share,
                                pathName=(
                                    remote_smb_fullpath
                                    + ntpath.sep
                                    + entry_file.get_longname()
                                ),
                                callback=f.write,
                            )
                            f.close()
                        except BrokenPipeError as err:
                            f.set_error(
                                message="[bold red]Failed downloading '%s': %s"
                                % (f.path, err)
                            )
                            f.close(remove=True)
                        except Exception as err:
                            f.set_error(
                                message="[bold red]Failed downloading '%s': %s"
                                % (f.path, err)
                            )
                            f.close(remove=True)

                # Directories
                for entry_directory in directories:
                    if entry_directory.is_directory():
                        recurse_action(
                            base_dir=self.smb_cwd,
                            path=path + [entry_directory.get_longname()],
                            localDownloadDir=localDownloadDir,
                        )

        if path is None:
            path = self.smb_cwd or ""
        # Entrypoint
        try:
            if path.startswith(ntpath.sep):
                base_dir = ntpath.dirname(path)
                path = ntpath.basename(path)
            else:
                base_dir = self.smb_cwd
                path = path

            recurse_action(
                base_dir=base_dir, path=[path], localDownloadDir=localDownloadDir
            )
        except (BrokenPipeError, KeyboardInterrupt):
            print("\x1b[v\x1b[o\r[!] Interrupted.")
            self.close_smb_session()
            self.init_smb_session()

    def get_entry(self, path: Optional[str] = None) -> Optional[SharedFile]:
        """
        Retrieves information about a specific entry located at the provided path on the SMB share.

        This method checks if the specified path exists on the SMB share. If the path exists, it retrieves the details of the entry at that path, including the directory name and file name. If the entry is found, it returns the entry object; otherwise, it returns None.

        Args:
            path (str): The path of the entry to retrieve information about.

        Returns:
            Entry: An object representing the entry at the specified path, or None if the entry is not found.
        """

        if self.path_exists(path=path):
            matches = self.smbClient.listPath(shareName=self.smb_share, path=path)

            if len(matches) == 1:
                return matches[0]
            else:
                return None
        else:
            return None

    def get_alternate_data_streams(self, path: str):
        """
        Retrieves alternate data streams (ADS) for a file at the specified path.

        This method is used to retrieve the alternate data streams (ADS) for a file at the specified path.
        It returns a list of dictionaries, each containing the name and size of the alternate data stream.

        Args:
            path (str): The path to the file for which to retrieve alternate data streams.

        Returns:
            list: A list of dictionaries, each containing the name and size of the alternate data stream.
        """
        ads_found = []

        entry = self.get_entry(path)
        if entry is None:
            self.logger.debug(f"File {path} not found")
            return []

        tree_id = self.smbClient.connectTree(self.smb_share)

        # Create a file handle
        try:
            file_id = self.smbClient.getSMBServer().create(
                tree_id,
                path,
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                0,
                (
                    FILE_DIRECTORY_FILE
                    if entry.is_directory()
                    else FILE_NON_DIRECTORY_FILE
                ),
                FILE_OPEN,
                0,
            )
        except Exception as err:
            self.logger.debug(f"Could not open handle for file {path}: {str(err)}")
            return []

        # Get file attributes
        try:
            raw_file_stream_info = self.smbClient.getSMBServer().queryInfo(
                tree_id,
                file_id,
                infoType=SMB2_0_INFO_FILE,
                fileInfoClass=SMB2_FILE_STREAM_INFO,
                additionalInformation=OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION,
                flags=0,
            )

            try:
                running = True
                if len(raw_file_stream_info) == 0:
                    running = False

                # Parse the file stream information
                while running:
                    try:
                        parsed_file_stream_info = SMBFileStreamInformation(
                            raw_file_stream_info
                        )
                        NextEntryOffset = parsed_file_stream_info.fields[
                            "NextEntryOffset"
                        ]
                        StreamNameLength = parsed_file_stream_info.fields[
                            "StreamNameLength"
                        ]
                        StreamName = parsed_file_stream_info.fields["StreamName"][
                            :StreamNameLength
                        ].decode("utf-16-le")

                        if StreamName.startswith(":") and StreamName.endswith(":$DATA"):
                            StreamName = StreamName[1:-6]

                        if len(StreamName) > 0:
                            # The base stream ::$DATA is not included in the list
                            ads_found.append(
                                {
                                    "Name": StreamName,
                                    "Size": parsed_file_stream_info.fields[
                                        "StreamSize"
                                    ],
                                }
                            )

                        if NextEntryOffset == 0:
                            running = False
                        else:
                            raw_file_stream_info = raw_file_stream_info[
                                NextEntryOffset:
                            ]

                    except Exception as err:
                        self.logger.debug(
                            f"Error parsing alternateDataStreams as impacket.smb.SMBFileStreamInformation for file {path}"
                        )
                        self.logger.debug(f"Error: {str(err)}")
                        running = False

                return ads_found

            except Exception as err:
                self.logger.debug(
                    f"Error parsing alternateDataStreams as impacket.smb.SMBFileStreamInformation for file {path}"
                )
                self.logger.debug(f"Error: {str(err)}")

        except Exception as err:
            self.logger.debug(f"Could not get attributes for file {path}: {str(err)}")

        return ads_found

    def info(self, share: bool = True, server: bool = True):
        """
        Displays information about the server and optionally the shares.

        This method prints detailed information about the server's characteristics such as NetBIOS names, DNS details, OS information, and SMB capabilities. If the `share` parameter is set to True and a share is currently set, it will also attempt to display information about the share.

        Parameters:
            share (bool): If True, display information about the current share.
            server (bool): If True, display information about the server.

        Returns:
            None
        """

        if server:
            if self.config.no_colors:
                self.logger.print("[+] Server:")
                self.logger.print("  ├─NetBIOS:")
                self.logger.print(
                    "  │ ├─ NetBIOS Hostname ──────── : %s"
                    % (self.smbClient.getServerName())
                )
                self.logger.print(
                    "  │ └─ NetBIOS Domain ────────── : %s"
                    % (self.smbClient.getServerDomain())
                )
                self.logger.print("  ├─DNS:")
                self.logger.print(
                    "  │ ├─ DNS Hostname ──────────── : %s"
                    % (self.smbClient.getServerDNSHostName())
                )
                self.logger.print(
                    "  │ └─ DNS Domain ────────────── : %s"
                    % (self.smbClient.getServerDNSDomainName())
                )
                self.logger.print("  ├─OS:")
                self.logger.print(
                    "  │ ├─ OS Name ───────────────── : %s"
                    % (self.smbClient.getServerOS())
                )
                self.logger.print(
                    "  │ └─ OS Version ────────────── : %s.%s.%s"
                    % (
                        self.smbClient.getServerOSMajor(),
                        self.smbClient.getServerOSMinor(),
                        self.smbClient.getServerOSBuild(),
                    )
                )
                self.logger.print("  ├─Server:")
                self.logger.print(
                    "  │ ├─ Signing Required ──────── : %s"
                    % (self.smbClient.isSigningRequired())
                )
                self.logger.print(
                    "  │ ├─ Login Required ────────── : %s"
                    % (self.smbClient.isLoginRequired())
                )
                self.logger.print(
                    "  │ ├─ Supports NTLMv2 ───────── : %s"
                    % (self.smbClient.doesSupportNTLMv2())
                )
                MaxReadSize = self.smbClient.getIOCapabilities()["MaxReadSize"]
                self.logger.print(
                    "  │ ├─ Max size of read chunk ── : %d bytes (%s)"
                    % (MaxReadSize, filesize(MaxReadSize))
                )
                MaxWriteSize = self.smbClient.getIOCapabilities()["MaxWriteSize"]
                self.logger.print(
                    "  │ └─ Max size of write chunk ─ : %d bytes (%s)"
                    % (MaxWriteSize, filesize(MaxWriteSize))
                )
                self.logger.print("  └─")
            else:
                self.logger.print("[+] Server:")
                self.logger.print("  ├─NetBIOS:")
                self.logger.print(
                    "  │ ├─ \x1b[94mNetBIOS Hostname\x1b[0m \x1b[90m────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (self.smbClient.getServerName())
                )
                self.logger.print(
                    "  │ └─ \x1b[94mNetBIOS Domain\x1b[0m \x1b[90m──────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (self.smbClient.getServerDomain())
                )
                self.logger.print("  ├─DNS:")
                self.logger.print(
                    "  │ ├─ \x1b[94mDNS Hostname\x1b[0m \x1b[90m────────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (self.smbClient.getServerDNSHostName())
                )
                self.logger.print(
                    "  │ └─ \x1b[94mDNS Domain\x1b[0m \x1b[90m──────────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (self.smbClient.getServerDNSDomainName())
                )
                self.logger.print("  ├─OS:")
                self.logger.print(
                    "  │ ├─ \x1b[94mOS Name\x1b[0m \x1b[90m─────────────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (self.smbClient.getServerOS())
                )
                self.logger.print(
                    "  │ └─ \x1b[94mOS Version\x1b[0m \x1b[90m──────────────\x1b[0m : \x1b[93m%s.%s.%s\x1b[0m"
                    % (
                        self.smbClient.getServerOSMajor(),
                        self.smbClient.getServerOSMinor(),
                        self.smbClient.getServerOSBuild(),
                    )
                )
                self.logger.print("  ├─Server:")
                self.logger.print(
                    "  │ ├─ \x1b[94mSigning Required\x1b[0m \x1b[90m────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (self.smbClient.isSigningRequired())
                )
                self.logger.print(
                    "  │ ├─ \x1b[94mLogin Required\x1b[0m \x1b[90m──────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (self.smbClient.isLoginRequired())
                )
                self.logger.print(
                    "  │ ├─ \x1b[94mSupports NTLMv2\x1b[0m \x1b[90m─────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (self.smbClient.doesSupportNTLMv2())
                )
                MaxReadSize = self.smbClient.getIOCapabilities()["MaxReadSize"]
                self.logger.print(
                    "  │ ├─ \x1b[94mMax size of read chunk\x1b[0m \x1b[90m──\x1b[0m : \x1b[93m%d bytes (%s)\x1b[0m"
                    % (MaxReadSize, filesize(MaxReadSize))
                )
                MaxWriteSize = self.smbClient.getIOCapabilities()["MaxWriteSize"]
                self.logger.print(
                    "  │ └─ \x1b[94mMax size of write chunk\x1b[0m \x1b[90m─\x1b[0m : \x1b[93m%d bytes (%s)\x1b[0m"
                    % (MaxWriteSize, filesize(MaxWriteSize))
                )
                self.logger.print("  └─")

        if share and self.smb_share is not None:
            share_name = self.available_shares.get(
                self.smb_share.lower(), {"name": ""}
            )["name"]
            share_comment = self.available_shares.get(
                self.smb_share.lower(), {"comment": ""}
            )["comment"]
            share_type = self.available_shares.get(
                self.smb_share.lower(), {"type": ""}
            )["type"]
            share_type = ", ".join([s.replace("STYPE_", "") for s in share_type])
            share_rawtype = self.available_shares.get(
                self.smb_share.lower(), {"rawtype": ""}
            )["rawtype"]
            if self.config.no_colors:
                self.logger.print("\n[+] Share:")
                self.logger.print("  ├─ Name ──────────── : %s" % (share_name))
                self.logger.print("  ├─ Description ───── : %s" % (share_comment))
                self.logger.print("  ├─ Type ──────────── : %s" % (share_type))
                self.logger.print("  └─ Raw type value ── : %s" % (share_rawtype))
            else:
                self.logger.print("\n[+] Share:")
                self.logger.print(
                    "  ├─ \x1b[94mName\x1b[0m \x1b[90m────────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (share_name)
                )
                self.logger.print(
                    "  ├─ \x1b[94mDescription\x1b[0m \x1b[90m─────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (share_comment)
                )
                self.logger.print(
                    "  ├─ \x1b[94mType\x1b[0m \x1b[90m────────────\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (share_type)
                )
                self.logger.print(
                    "  └─ \x1b[94mRaw type value\x1b[0m \x1b[90m──\x1b[0m : \x1b[93m%s\x1b[0m"
                    % (share_rawtype)
                )

    def list_contents(self, path: Optional[str] = None) -> dict[str, SharedFile]:
        """
        Lists the contents of a specified directory on the SMB share.

        This method retrieves the contents of a directory specified by `shareName` and `path`. If `shareName` or `path`
        is not provided, it defaults to the instance's current SMB share or path. The method returns a dictionary with
        the long names of the files and directories as keys and their respective SMB entry objects as values.

        Args:
            shareName (str, optional): The name of the SMB share. Defaults to the current SMB share if None.
            path (str, optional): The directory path to list contents from. Defaults to the current path if None.

        Returns:
            dict: A dictionary with file and directory names as keys and their SMB entry objects as values.
        """

        dest_path = [
            self.smb_cwd.rstrip(ntpath.sep),
        ]
        if path is not None and len(path) > 0:
            dest_path.append(path.rstrip(ntpath.sep))
        dest_path.append("*")
        path = ntpath.normpath(ntpath.sep.join(dest_path))

        contents = {}
        try:
            entries = self.smbClient.listPath(shareName=self.smb_share, path=path)
            for entry in entries:
                contents[entry.get_longname()] = entry
        except SessionError as err:
            if self.config.debug:
                traceback.print_exc()
            self.logger.error(str(err))

        return contents

    def printSecurityDescriptorTable(
        self,
        security_descriptor: str,
        subject: str,
        prefix: str = " " * 13,
        table_colors: bool = False,
    ):
        self.logger.print(
            self.securityDescriptorTable(
                security_descriptor, subject, prefix, table_colors
            )
        )

    def securityDescriptorTable(
        self,
        security_descriptor: str,
        subject: str,
        prefix: str = " " * 13,
        table_colors: bool = False,
    ) -> str:
        if security_descriptor is not None and len(security_descriptor) == 0:
            return ""
        out_sd = ""
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(security_descriptor)
        try:
            self.sid_resolver.resolve_sids(
                set(
                    (
                        [sd["OwnerSid"].formatCanonical()]
                        if len(sd["OwnerSid"]) != 0
                        else []
                    )
                    + (
                        [sd["GroupSid"].formatCanonical()]
                        if len(sd["GroupSid"]) != 0
                        else []
                    )
                    + [
                        acl["Ace"]["Sid"].formatCanonical()
                        for acl in sd["Dacl"]["Data"]
                        if len(acl["Ace"]["Sid"]) != 0
                    ]
                )
            )
        except Exception as err:
            self.logger.debug(f"Could not resolve SID for {subject}: {str(err)}")
            traceback.print_exc()
        max_resolved_sid_length = max(
            [len(i) for i in self.sid_resolver.cache.values()] + [0]
        )

        if len(sd["OwnerSid"]) != 0:
            resolved_owner_sid = self.sid_resolver.get_sid(
                sd["OwnerSid"].formatCanonical()
            )
            resolved_group_sid = self.sid_resolver.get_sid(
                sd["GroupSid"].formatCanonical()
            )

            if self.config.no_colors:
                out_sd += f"{prefix}Owner:   {resolved_owner_sid}\n"
                out_sd += f"{prefix}Group:   {resolved_group_sid}"
            else:
                if table_colors:
                    out_sd += f"{prefix}Owner:   [bold yellow]{resolved_owner_sid}[/bold yellow]\n"
                    out_sd += f"{prefix}Group:   [bold yellow]{resolved_group_sid}[/bold yellow]"
                else:
                    out_sd += f"{prefix}Owner:   \x1b[1m{resolved_owner_sid}\x1b[0m\n"
                    out_sd += f"{prefix}Group:   \x1b[1m{resolved_group_sid}\x1b[0m"

        for i, acl in enumerate(sd["Dacl"]["Data"]):
            resolved_sid = (
                acl["Ace"]["Sid"].formatCanonical()
                if len(acl["Ace"]["Sid"]) != 0
                else ""
            )
            if resolved_sid in ["S-1-5-32-544", "S-1-5-18"]:
                continue

            flags = []
            for flag in [
                "GENERIC_READ",
                "GENERIC_WRITE",
                "GENERIC_EXECUTE",
                "GENERIC_ALL",
                "MAXIMUM_ALLOWED",
                "ACCESS_SYSTEM_SECURITY",
                "WRITE_OWNER",
                "WRITE_DACL",
                "DELETE",
                "READ_CONTROL",
                "SYNCHRONIZE",
            ]:
                if len(acl["Ace"]["Mask"]) != 0 and acl["Ace"]["Mask"].hasPriv(
                    getattr(ldaptypes.ACCESS_MASK, flag)
                ):
                    flags.append(flag)
            if len(flags) == 0:
                continue
            try:
                resolved_sid = (
                    self.sid_resolver.get_sid(resolved_sid) if resolved_sid else ""
                )
            except Exception as err:
                self.logger.debug(
                    f"Could not resolve SID {resolved_sid} for {subject}: {str(err)}"
                )

            acl_string = prefix
            inbetween = ""
            if len(resolved_sid) < max_resolved_sid_length + 1:
                inbetween = " " * (max_resolved_sid_length + 1 - len(resolved_sid))

            if self.config.no_colors:
                acl_string += f"{resolved_sid}" + " | ".join(flags)
            else:
                acl_string += (
                    "Allowed: "
                    if acl["TypeName"] == "ACCESS_ALLOWED_ACE"
                    else "Denied:  "
                )
                if table_colors:
                    acl_string += f"[bold yellow]{resolved_sid}[/bold yellow]"
                else:
                    acl_string += f"\x1b[1m{resolved_sid}\x1b[0m"
                acl_string += inbetween
                acl_string += " | ".join(flags)
            out_sd += "\n" + acl_string
        return out_sd.lstrip("\n")

    def listSharesDetailed(self) -> dict:
        """
        get a list of available shares at the connected target

        :return: a list containing dict entries for each share
        :raise SessionError: if error
        """
        # Get the shares through RPC
        resp = srvs.hNetrShareEnum(
            self.dce_srvsvc, 502, serverName="\\\\" + self.smbClient.getRemoteHost()
        )
        return resp["InfoStruct"]["ShareInfo"]["Level502"]["Buffer"]

    def list_shares(self) -> dict[str, dict]:
        """
        Lists all the shares available on the connected SMB server.

        This method queries the SMB server to retrieve a list of all available shares. It populates the `shares` dictionary
        with key-value pairs where the key is the share name and the value is a dictionary containing details about the share
        such as its name, type, raw type, and any comments associated with the share.

        Returns:
            dict: A dictionary containing information about each share available on the server.
        """

        self.available_shares = {}

        if self.connected:
            if self.smbClient is not None:
                try:
                    resp = self.listSharesDetailed()
                    for share in resp:
                        # SHARE_INFO_502 structure (lmshare.h)
                        # https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_502
                        sharename = share["shi502_netname"][:-1]
                        sharecomment = share["shi502_remark"][:-1]
                        sharetype = share["shi502_type"]
                        sharesd = share["shi502_security_descriptor"]

                        self.available_shares[sharename.lower()] = {
                            "name": sharename,
                            "type": STYPE_MASK(sharetype),
                            "rawtype": sharetype,
                            "comment": sharecomment,
                            "security_descriptor": sharesd,
                        }
                except Exception as err:
                    self.logger.debug(f"Could not get detailed share info: {str(err)}")
                    resp = self.smbClient.listShares()

                    for share in resp:
                        # SHARE_INFO_1 structure (lmshare.h)
                        # https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_1
                        sharename = share["shi1_netname"][:-1]
                        sharecomment = share["shi1_remark"][:-1]
                        sharetype = share["shi1_type"]

                        self.available_shares[sharename.lower()] = {
                            "name": sharename,
                            "type": STYPE_MASK(sharetype),
                            "rawtype": sharetype,
                            "comment": sharecomment,
                        }

            else:
                self.logger.error("Error: SMBSession.smbClient is None.")

        return self.available_shares

    def mkdir(self, path: str):
        """
        Creates a directory at the specified path on the SMB share.

        This method takes a path and attempts to create the directory structure on the SMB share. If the path includes
        nested directories, it will create each directory in the sequence. If a directory already exists, it will skip
        the creation for that directory without raising an error.

        Args:
            path (str): The full path of the directory to create on the SMB share. Defaults to None.

        Note:
            The path should use forward slashes ('/') which will be converted to backslashes (ntpath.sep) for SMB compatibility.
        """

        # Prepare path
        split_path = path.replace("/", ntpath.sep)
        if ntpath.sep in path:
            split_path = path.strip(ntpath.sep).split(ntpath.sep)
        else:
            split_path = [split_path]

        # Create each dir in the path
        for depth in range(1, len(split_path) + 1):
            tmp_path = ntpath.sep.join(split_path[:depth])
            try:
                self.smbClient.createDirectory(
                    shareName=self.smb_share,
                    pathName=ntpath.normpath(
                        self.smb_cwd + ntpath.sep + tmp_path + ntpath.sep
                    ),
                )
            except SessionError as err:
                if err.getErrorCode() == STATUS_OBJECT_NAME_COLLISION:
                    # Remote directory already created, this is normal
                    # Src: https://github.com/fortra/impacket/blob/269ce69872f0e8f2188a80addb0c39fedfa6dcb8/impacket/nt_errors.py#L268C9-L268C19
                    pass
                else:
                    self.logger.error(
                        "Failed to create directory '%s': %s" % (tmp_path, err)
                    )
                    if self.config.debug:
                        traceback.print_exc()

    def mount(self, local_mount_point: str, remote_path: str):
        """
        Generates the command to mount an SMB share on different platforms.

        This method takes the local mount point and the remote path of the SMB share and generates the appropriate mount command based on the platform.
        It constructs the mount command using the provided parameters and executes it using the os.system() function.

        Args:
            local_mount_point (str): The local directory where the SMB share will be mounted.
            remote_path (str): The remote path on the SMB share to be mounted.

        Note:
            - For Windows platform, the command uses 'net use' to mount the share.
            - For Linux platform, the command uses 'mount' to mount the share.
            - For macOS platform, the command uses 'mount_smbfs' to mount the share.
            - If the platform is not supported, an error message is displayed.

        Returns:
            None
        """

        executable = None
        args = None

        if not os.path.exists(local_mount_point):
            pass

        if sys.platform.startswith("win"):
            remote_path = remote_path.replace("/", ntpath.sep)

            executable = "net"
            args = [
                "use",
                f"{local_mount_point}",
                f"\\\\{self.host}\\{self.smb_share}\\{remote_path}",
            ]

        elif sys.platform.startswith("linux"):
            remote_path = remote_path.replace(ntpath.sep, "/")
            password = self.credentials.password.replace('"', '\\"')

            executable = "mount"
            args = [
                "-t",
                "cifs",
                f"//{self.host}/{self.smb_share}/{remote_path}",
                f"{local_mount_point}",
                "-o",
                f"username={self.credentials.username},password={password}",
            ]

        elif sys.platform.startswith("darwin"):
            remote_path = remote_path.replace(ntpath.sep, "/")
            password = self.credentials.password.replace('"', '\\"')

            executable = "mount_smbfs"
            args = [
                f"//{self.credentials.username}:{self.credentials.password}@{self.host}/{self.smb_share}/{remote_path}",
                f"{local_mount_point}",
            ]

        else:
            executable = None
            args = None
            self.logger.error("Unsupported platform for mounting SMB share.")

        if executable is not None:
            if self.config.debug:
                self.logger.debug(
                    "Executing '%s' with arguments: %s" % (executable, args)
                )
            process = subprocess.Popen(
                executable=executable,
                args=args,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                self.logger.error("Command failed with error: %s" % stderr.decode())
            else:
                output = stdout.decode()
                if len(output) != 0:
                    self.logger.debug("Command output: %s" % stdout.decode())
                self.logger.info(
                    f"Successfully mounted '\\\\{self.host}\\{self.smb_share}\\{remote_path}' to local '{local_mount_point}'."
                )

    def path_exists(self, path: Optional[str] = None):
        """
        Checks if the specified path exists on the SMB share.

        This method determines if a given path exists on the SMB share by attempting to list the contents of the path.
        If the path listing is successful and returns one or more entries, the path is considered to exist.

        Args:
            path (str, optional): The path to check on the SMB share. Defaults to None.

        Returns:
            bool: True if the path exists, False otherwise or if an error occurs.
        """

        if path is not None:
            path = path.replace("*", "")
            path = path.replace("/", ntpath.sep)

            if path.startswith(ntpath.sep):
                full_path = ntpath.normpath(path)
            else:
                full_path = ntpath.normpath(
                    self.smb_cwd + ntpath.sep + path + ntpath.sep
                )

            try:
                contents = self.smbClient.listPath(
                    shareName=self.smb_share, path=full_path
                )
                return len(contents) != 0
            except Exception:
                return False
        else:
            return False

    def path_isdir(self, pathFromRoot: Optional[str] = None):
        """
        Checks if the specified path is a directory on the SMB share.

        This method determines if a given path corresponds to a directory on the SMB share. It does this by listing the
        contents of the path and filtering for entries that match the basename of the path and are marked as directories.

        Args:
            path (str, optional): The path to check on the SMB share. Defaults to None.

        Returns:
            bool: True if the path is a directory, False otherwise or if an error occurs.
        """

        if pathFromRoot is not None:
            # Strip wildcards to avoid injections
            path = pathFromRoot.replace("*", "")
            # Replace slashes if any
            path = path.replace("/", ntpath.sep)

            # Normalize path and strip leading backslash
            path = ntpath.normpath(path + ntpath.sep).lstrip(ntpath.sep)

            if path.strip() in ["", ".", ".."]:
                # By defininition they exist on the filesystem
                return True
            else:
                try:
                    contents = self.smbClient.listPath(
                        shareName=self.smb_share, path=path + "*"
                    )
                    # Filter on directories
                    contents = [
                        c
                        for c in contents
                        if c.get_longname() == ntpath.basename(path)
                        and c.is_directory()
                    ]
                    return len(contents) != 0
                except Exception:
                    return False
        else:
            return False

    def path_isfile(self, pathFromRoot: Optional[str] = None):
        """
        Checks if the specified path is a file on the SMB share.

        This method determines if a given path corresponds to a file on the SMB share. It does this by listing the
        contents of the path and filtering for entries that match the basename of the path and are not marked as directories.

        Args:
            path (str, optional): The path to check on the SMB share. Defaults to None.

        Returns:
            bool: True if the path is a file, False otherwise or if an error occurs.
        """

        if pathFromRoot is not None:
            # Strip wildcards to avoid injections
            path = pathFromRoot.replace("*", "")
            # Replace slashes if any
            path = path.replace("/", ntpath.sep)

            # Normalize path and strip leading backslash
            path = ntpath.normpath(path + ntpath.sep).lstrip(ntpath.sep)

            basename = ntpath.basename(path)
            if ":" in basename:
                path = basename.split(":", 1)[0]
                # stream_name =basename.split(":", 1)[1]

            try:
                contents = self.smbClient.listPath(
                    shareName=self.smb_share,
                    path=ntpath.dirname(path) + ntpath.sep + "*",
                )
                # Filter on files
                contents = [
                    c
                    for c in contents
                    if c.get_longname() == ntpath.basename(path)
                    and not c.is_directory()
                ]
                return len(contents) != 0
            except Exception:
                return False
        else:
            return False

    def put_file(self, localpath: str):
        """
        Uploads a single file to the SMB share.

        This method takes a local file path, opens the file, and uploads it to the SMB share at the specified path.
        It handles exceptions such as broken pipe errors or keyboard interrupts by closing and reinitializing the SMB session.
        General exceptions are caught and logged, with a traceback provided if debugging is enabled.

        Args:
            localpath (str, optional): The local file path of the file to be uploaded. Defaults to None.
        """

        # Parse path
        localpath = localpath.replace("/", os.path.sep)
        if os.path.sep in localpath:
            if localpath.startswith(os.path.sep):
                # Absolute path
                tmp_search_path = os.path.normpath(localpath)
            else:
                # Relative path
                tmp_search_path = os.path.normpath(
                    os.getcwd() + os.path.sep + os.path.dirname(localpath)
                )
        else:
            tmp_search_path = os.path.normpath(os.getcwd() + os.path.sep)

        # Parse filename
        filename = os.path.basename(localpath)

        # Search for the file
        matches = os.listdir(tmp_search_path)
        # Filter the entries
        matching_entries = []
        for entry in matches:
            if entry == filename:
                matching_entries.append(entry)
            elif "*" in filename:
                regexp = filename.replace(".", "\\.").replace("*", ".*")
                if re.match(regexp, entry):
                    matching_entries.append(entry)

        matching_entries = sorted(list(set(matching_entries)))

        # Loop and upload
        for localpath in matching_entries:
            if os.path.exists(localpath):
                if os.path.isfile(localpath):
                    try:
                        localfile = os.path.basename(localpath)
                        f = LocalFileIO(mode="rb", path=localpath, logger=self.logger)
                        self.smbClient.putFile(
                            shareName=self.smb_share,
                            pathName=ntpath.normpath(
                                self.smb_cwd + ntpath.sep + localfile + ntpath.sep
                            ),
                            callback=f.read,
                        )
                        f.close()

                    except (BrokenPipeError, KeyboardInterrupt):
                        self.logger.error("Interrupted.")
                        self.close_smb_session()
                        self.init_smb_session()

                    except (Exception, PermissionError) as err:
                        f.set_error(
                            message="[bold red]Failed uploading '%s': %s"
                            % (f.path, err)
                        )
                        f.close(remove=False)
                        if self.config.debug:
                            traceback.print_exc()
                else:
                    # [!] The specified localpath is a directory. Use 'put -r <directory>' instead.
                    pass
            else:
                # [!] The specified localpath does not exist.
                pass

    def put_file_recursively(self, localpath: Optional[str] = None):
        """
        Recursively uploads files from a specified local directory to the SMB share.

        This method walks through the given local directory and all its subdirectories, uploading each file to the
        corresponding directory structure on the SMB share. It first checks if the local path is a directory. If it is,
        it iterates over all files and directories within the local path, creating necessary directories on the SMB share
        and uploading files. If the local path is not a directory, it prints an error message.

        Args:
            localpath (str, optional): The local directory path from which files will be uploaded. Defaults to None.
        """

        if localpath is None:
            localpath = "./"

        if os.path.exists(localpath):
            if os.path.isdir(localpath):
                # Iterate over all files and directories within the local path
                local_files = {}
                for root, dirs, files in os.walk(localpath):
                    if len(files) != 0:
                        local_files[root] = files

                # Iterate over the found files
                for local_dir_path in sorted(local_files.keys()):
                    self.logger.print("[>] Putting files of '%s'" % local_dir_path)

                    # Create remote directory
                    remote_dir_path = local_dir_path.replace(os.path.sep, ntpath.sep)
                    self.mkdir(path=ntpath.normpath(remote_dir_path + ntpath.sep))

                    for local_file_path in local_files[local_dir_path]:
                        try:
                            f = LocalFileIO(
                                mode="rb",
                                path=local_dir_path + os.path.sep + local_file_path,
                                logger=self.logger,
                            )
                            self.smbClient.putFile(
                                shareName=self.smb_share,
                                pathName=ntpath.normpath(
                                    self.smb_cwd
                                    + ntpath.sep
                                    + remote_dir_path
                                    + ntpath.sep
                                    + local_file_path
                                ),
                                callback=f.read,
                            )
                            f.close()

                        except (BrokenPipeError, KeyboardInterrupt):
                            self.logger.error("Interrupted.")
                            self.close_smb_session()
                            self.init_smb_session()

                        except (Exception, PermissionError) as err:
                            f.set_error(
                                message="[bold red]Failed uploading '%s': %s"
                                % (f.path, err)
                            )
                            f.close(remove=False)
                            if self.config.debug:
                                traceback.print_exc()
                else:
                    self.logger.error(
                        "The specified localpath is a file. Use 'put <file>' instead."
                    )
        else:
            self.logger.error("The specified localpath does not exist.")

    def read_file(self, path: Optional[str] = None):
        """
        Reads a file from the SMB share.

        This method attempts to read the contents of a file specified by the `path` parameter from the SMB share.
        It constructs the full path to the file, checks if the path is a valid file, and then reads the file content
        into a byte stream which is returned to the caller.

        Args:
            path (str, optional): The path of the file to be read from the SMB share. Defaults to None.

        Returns:
            bytes: The content of the file as a byte stream, or None if the file does not exist or an error occurs.
        """

        if self.path_isfile(pathFromRoot=path):
            path = path.replace("/", ntpath.sep)

            path = normalize_alternate_data_stream_path(path)

            if path.startswith(ntpath.sep):
                # Absolute path
                tmp_file_path = ntpath.normpath(path)
            else:
                # Relative path
                tmp_file_path = ntpath.normpath(self.smb_cwd + ntpath.sep + path)
            tmp_file_path = tmp_file_path.lstrip(ntpath.sep)

            fh = io.BytesIO()
            try:
                # opening the files in streams instead of mounting shares allows
                # for running the script from unprivileged containers
                self.smbClient.getFile(self.smb_share, tmp_file_path, fh.write)
            except SessionError:
                return None
            rawdata = fh.getvalue()
            fh.close()
            return rawdata
        else:
            return None

    def rmdir(self, path: str):
        """
        Removes a directory from the SMB share at the specified path.

        This method attempts to delete a directory located at the given path on the SMB share. If the operation fails,
        it prints an error message indicating the failure and the reason. If debugging is enabled, it also prints
        the stack trace of the exception.

        Args:
            path (str): The path of the directory to be removed on the SMB share. Defaults to None.
        """

        try:
            self.smbClient.deleteDirectory(
                shareName=self.smb_share,
                pathName=ntpath.normpath(self.smb_cwd + ntpath.sep + path),
            )
        except Exception as err:
            self.logger.error("Failed to remove directory '%s': %s" % (path, err))
            if self.config.debug:
                traceback.print_exc()

    def rm(self, path: str):
        """
        Removes a file from the SMB share at the specified path.

        This method attempts to delete a file located at the given path on the SMB share. If the operation fails,
        it prints an error message indicating the failure and the reason. If debugging is enabled, it also prints
        the stack trace of the exception.

        Args:
            path (str): The path of the file to be removed on the SMB share. Defaults to None.
        """

        # Parse path
        path = path.replace("/", ntpath.sep)
        if ntpath.sep in path:
            tmp_search_path = ntpath.normpath(
                self.smb_cwd + ntpath.sep + ntpath.dirname(path)
            )
        else:
            tmp_search_path = ntpath.normpath(self.smb_cwd + ntpath.sep)
        # Parse filename
        filename = ntpath.basename(path)

        # Search for the file
        matches = self.smbClient.listPath(
            shareName=self.smb_share, path=tmp_search_path + ntpath.sep + "*"
        )

        # Filter the entries
        matching_entries = []
        for entry in matches:
            if entry.is_directory():
                # Skip directories
                continue
            if entry.get_longname() == filename:
                matching_entries.append(entry)
            elif "*" in filename:
                regexp = filename.replace(".", "\\.").replace("*", ".*")
                if re.match(regexp, entry.get_longname()):
                    matching_entries.append(entry)

        matching_entries = sorted(
            list(set(matching_entries)), key=lambda x: x.get_longname()
        )

        for entry in matching_entries:
            try:
                self.smbClient.deleteFile(
                    shareName=self.smb_share,
                    pathName=ntpath.normpath(
                        tmp_search_path + ntpath.sep + entry.get_longname()
                    ),
                )
            except Exception as err:
                self.logger.error("Failed to remove file '%s': %s" % (path, err))
                if self.config.debug:
                    traceback.print_exc()

    def tree(
        self,
        path: Optional[str] = None,
        quiet: bool = False,
        outputfile: Optional[str] = None,
    ):
        """
        Recursively lists the directory structure of the SMB share starting from the specified path.

        This function prints a visual representation of the directory tree of the remote SMB share. It uses
        recursion to navigate through directories and lists all files and subdirectories in each directory.
        The output is color-coded and formatted to enhance readability, with directories highlighted in cyan.

        Args:
            path (str, optional): The starting path on the SMB share from which to begin listing the tree.
                                  Defaults to the root of the current share.
        """

        if path is None:
            path = self.smb_cwd or ""

        # Normalize and parse the path
        path = path.replace("/", ntpath.sep)

        # Handle relative and absolute paths
        if not ntpath.isabs(path):
            path = ntpath.normpath(ntpath.join(self.smb_cwd or "", path))
        else:
            path = path.lstrip(ntpath.sep)
            path = ntpath.normpath(path)

        # Prepare output file
        if outputfile is not None:
            os.makedirs(os.path.dirname(outputfile), exist_ok=True)
            open(outputfile, "w").close()

        # Initialize variables
        prefix_stack = []
        prev_is_last = False

        try:
            # Initialize the generator
            generator = smb_entry_iterator(
                smb_client=self.smbClient,
                smb_share=self.smb_share,
                start_paths=[path],
                exclusion_rules=[],
                max_depth=None,
            )

            last_depth = -1
            for entry, fullpath, depth, is_last_entry in generator:
                # Adjust the prefix stack based on the current depth
                if depth > last_depth:
                    if last_depth >= 0:
                        prefix_stack.append("│   " if not prev_is_last else "    ")
                elif depth < last_depth:
                    prefix_stack = prefix_stack[:depth]

                # Determine the connector
                connector = "└── " if is_last_entry else "├── "

                # Build the prefix
                prefix = "".join(prefix_stack)

                # Format the entry name
                entry_name = entry.get_longname()
                if entry.is_directory():
                    if not self.config.no_colors:
                        entry_display = f"\x1b[1;96m{entry_name}\x1b[0m/"
                    else:
                        entry_display = f"{entry_name}/"
                else:
                    entry_display = entry_name

                line = f"{prefix}{connector}{entry_display}"

                # Output
                if not quiet:
                    self.logger.print(line)

                if outputfile is not None:
                    with open(outputfile, "a") as f:
                        f.write(f"{line}\n")

                # Update variables for next iteration
                last_depth = depth
                prev_is_last = is_last_entry

        except (BrokenPipeError, KeyboardInterrupt):
            self.logger.error("Interrupted.")
            self.close_smb_session()
            self.init_smb_session()
        except Exception as e:
            self.logger.error(f"Error during tree traversal: {e}")
            if self.config.debug:
                traceback.print_exc()

    def umount(self, local_mount_point: str):
        """
        Unmounts the specified local mount point of the remote share.

        This method unmounts the specified local mount point of the remote share based on the platform.
        It supports Windows, Linux, and macOS platforms for unmounting.

        Parameters:
            local_mount_point (str): The local mount point to unmount.

        Raises:
            None
        """

        if os.path.exists(local_mount_point):
            if sys.platform.startswith("win"):
                executable = "net"
                args = ["use", f"{local_mount_point}", "/delete"]

            elif sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
                executable = "umount"
                args = [f"{local_mount_point}"]

            else:
                executable = None
                args = None
                self.logger.error("Unsupported platform for unmounting SMB share.")

            if executable is not None:
                if self.config.debug:
                    self.logger.debug(
                        "Executing '%s' with arguments: %s" % (executable, args)
                    )
                process = subprocess.Popen(
                    executable=executable,
                    args=args,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, stderr = process.communicate()
                if process.returncode != 0:
                    self.logger.error("Command failed with error: %s" % stderr.decode())
                else:
                    output = stdout.decode()
                    if len(output) != 0:
                        self.logger.debug("Command output: %s" % stdout.decode())
                    self.logger.info(
                        f"Successfully unmounted local path '{local_mount_point}'."
                    )
        else:
            self.logger.error("Cannot unmount a non existing path.")

    # Other functions

    def test_rights(self, sharename: str, test_write: bool = False):
        """
        Tests the read and write access rights of the current SMB session.

        This method checks the read and write access rights of the current SMB session by attempting to list paths and create/delete temporary directories.

        Returns:
            dict: A dictionary containing the read and write access rights status.
                - "readable" (bool): Indicates if the session has read access rights.
                - "writable" (bool): Indicates if the session has write access rights.
        """

        # Restore the current share
        current_share = self.smb_share
        current_cwd = self.smb_cwd
        try:
            self.set_share(shareName=sharename)
        except Exception:
            self.set_share(shareName=current_share)
            self.smb_cwd = current_cwd
            return {"readable": False, "writable": False}

        access_rights = {"readable": False, "writable": False}

        # READ
        try:
            self.smbClient.listPath(self.smb_share, "*", password=None)
            access_rights["readable"] = True
        except SessionError:
            access_rights["readable"] = False

        if test_write:
            # WRITE
            try:
                temp_dir = ntpath.normpath(
                    "\\"
                    + "".join(
                        [
                            random.choice(
                                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPRSTUVWXYZ0123456759"
                            )
                            for k in range(16)
                        ]
                    )
                )
                self.smbClient.createDirectory(self.smb_share, temp_dir)
                self.smbClient.deleteDirectory(self.smb_share, temp_dir)
                access_rights["writable"] = True
            except SessionError:
                access_rights["writable"] = False

        # Restore the current share
        self.set_share(shareName=current_share)
        self.smb_cwd = current_cwd

        return access_rights

    # Setter / Getter

    def set_share(self, shareName: str):
        """
        Sets the current SMB share to the specified share name.

        This method updates the SMB session to use the specified share name. It checks if the share name is valid
        and updates the smb_share attribute of the SMBSession instance.

        Parameters:
            shareName (str): The name of the share to set as the current SMB share.

        Raises:
            ValueError: If the shareName is None or an empty string.
        """

        if shareName is not None:
            self.list_shares()
            if shareName.lower() in self.available_shares.keys():
                # Doing this in order to keep the case of the share adevertised by the remote machine
                self.smb_share = self.available_shares[shareName.lower()]["name"]
                self.smb_cwd = ""
                # Connects the tree
                try:
                    self.smb_tree_id = self.smbClient.connectTree(self.smb_share)
                except SessionError as err:
                    if self.config.debug:
                        traceback.print_exc()
                    self.logger.error("Could not access share '%s': %s" % (shareName, err))
                    self.smb_share = None
                    self.smb_cwd = ""
            else:
                self.logger.error(
                    "Could not set share '%s', it does not exist remotely." % shareName
                )
        else:
            self.smb_share = None

    def set_cwd(self, path: Optional[str] = None):
        """
        Sets the current working directory on the SMB share to the specified path.

        This method updates the current working directory (cwd) of the SMB session to the given path if it is a valid directory.
        If the specified path is not a directory, the cwd remains unchanged.

        Parameters:
            path (str): The path to set as the current working directory.

        Raises:
            ValueError: If the specified path is not a directory.
        """

        if path is not None:
            # Set path separators to ntpath sep
            if "/" in path:
                path = path.replace("/", ntpath.sep)

            if path.startswith(ntpath.sep):
                # Absolute path
                path = path + ntpath.sep
            else:
                # Relative path to the CWD
                if len(self.smb_cwd) == 0:
                    path = path + ntpath.sep
                else:
                    path = self.smb_cwd + ntpath.sep + path

            # Path normalization
            path = ntpath.normpath(path)
            path = re.sub(r"\\+", r"\\", path)

            if path in ["", ".", ".."]:
                self.smb_cwd = ""
            else:
                if self.path_isdir(pathFromRoot=path.strip(ntpath.sep)):
                    # Path exists on the remote
                    self.smb_cwd = ntpath.normpath(path)
                else:
                    # Path does not exists or is not a directory on the remote
                    self.logger.error("Remote directory '%s' does not exist." % path)
