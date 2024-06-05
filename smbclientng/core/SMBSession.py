#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : smbclient-ng.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 may 2024


import io
import impacket.smbconnection
import ntpath
import os
import re
import traceback
from smbclientng.core.LocalFileIO import LocalFileIO
from smbclientng.core.utils import b_filesize, STYPE_MASK


class SMBSession(object):
    """
    Class SMBSession is designed to handle the session management for SMB (Server Message Block) protocol connections.
    It provides functionalities to connect to an SMB server, authenticate using either NTLM or Kerberos, and manage SMB shares.

    Attributes:
        address (str): The IP address or hostname of the SMB server.
        domain (str): The domain name for SMB server authentication.
        username (str): The username for SMB server authentication.
        password (str): The password for SMB server authentication.
        lmhash (str): The LM hash of the user's password, if available.
        nthash (str): The NT hash of the user's password, if available.
        use_kerberos (bool): A flag to determine whether to use Kerberos for authentication.
        kdcHost (str): The Key Distribution Center (KDC) host for Kerberos authentication.
        debug (bool): A flag to enable debug output.
        smbClient (object): The SMB client object used for the connection.
        connected (bool): A flag to check the status of the connection.
        smb_share (str): The current SMB share in use.
        smb_path (str): The current path within the SMB share.

    Methods:
        __init__(address, domain, username, password, lmhash, nthash, use_kerberos=False, kdcHost=None, debug=False):
            Initializes the SMBSession with the specified parameters.
        init_smb_session():
            Initializes the SMB session by connecting to the server and authenticating using the specified method.
    """

    def __init__(self, address, domain, username, password, lmhash, nthash, use_kerberos=False, kdcHost=None, config=None):
        super(SMBSession, self).__init__()
        # Objects
        self.config = config

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

        self.available_shares = {}
        self.smb_share = None
        self.smb_cwd = ""

        self.list_shares()

    # Connect and disconnect SMB session

    def init_smb_session(self):
        """
        Initializes and establishes a session with the SMB server.

        This method sets up the SMB connection using either Kerberos or NTLM authentication based on the configuration.
        It attempts to connect to the SMB server specified by the `address` attribute and authenticate using the credentials provided during the object's initialization.

        The method will print debug information if the `debug` attribute is set to True. Upon successful connection and authentication, it sets the `connected` attribute to True.

        Returns:
            bool: True if the connection and authentication are successful, False otherwise.
        """

        self.connected = False

        if self.config.debug:
            print("[debug] [>] Connecting to remote SMB server '%s' ... " % self.address)
        try:
            self.smbClient = impacket.smbconnection.SMBConnection(
                remoteName=self.address,
                remoteHost=self.address,
                sess_port=int(445)
            )
        except OSError as err:
            print("[!] %s" % err)
            self.smbClient = None

        if self.smbClient is not None:
            if self.use_kerberos:
                if self.config.debug:
                    print("[debug] [>] Authenticating as '%s\\%s' with kerberos ... " % (self.domain, self.username))
                try:
                    self.connected = self.smbClient.kerberosLogin(
                        user=self.username,
                        password=self.password,
                        domain=self.domain,
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        aesKey=self.aesKey,
                        kdcHost=self.kdcHost
                    )
                except impacket.smbconnection.SessionError as err:
                    if self.config.debug:
                        traceback.print_exc()
                    print("[!] Could not login: %s" % err)
                    self.connected = False

            else:
                if self.config.debug:
                    print("[debug] [>] Authenticating as '%s\\%s' with NTLM ... " % (self.domain, self.username))
                try:
                    self.connected = self.smbClient.login(
                        user=self.username,
                        password=self.password,
                        domain=self.domain,
                        lmhash=self.lmhash,
                        nthash=self.nthash
                    )
                except impacket.smbconnection.SessionError as err:
                    if self.config.debug:
                        traceback.print_exc()
                    print("[!] Could not login: %s" % err)
                    self.connected = False

            if self.connected:
                print("[+] Successfully authenticated to '%s' as '%s\\%s'!" % (self.address, self.domain, self.username))
            else:
                print("[!] Failed to authenticate to '%s' as '%s\\%s'!" % (self.address, self.domain, self.username))

        return self.connected

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
                if self.config.debug:
                    print("[+] SMB connection closed successfully.")
            else:
                if self.config.debug:
                    print("[!] No active SMB connection to close.")
        else:
            raise Exception("SMB client is not initialized.")

    # Operations

    def read_file(self, path=None):
        if self.path_isfile(path=path):
            tmp_file_path = self.smb_cwd + ntpath.sep + path
            matches = self.smbClient.listPath(
                shareName=self.smb_share, 
                path=tmp_file_path
            )

            fh = io.BytesIO()
            try:
                # opening the files in streams instead of mounting shares allows 
                # for running the script from unprivileged containers
                self.smbClient.getFile(self.smb_share, tmp_file_path, fh.write)
            except impacket.smbconnection.SessionError as e:
                return None
            rawdata = fh.getvalue()
            fh.close()
            return rawdata
        else:
            print("[!] Remote path '%s' is not a file." % path)

    def find(self, paths=[], callback=None):
        def recurse_action(paths=[], depth=0, callback=None):
            if callback is None:
                return []
            
            next_directories_to_explore = []

            for path in paths:
                remote_smb_path = ntpath.normpath(self.smb_cwd + ntpath.sep + path)
                entries = []
                
                try:
                    entries = self.smbClient.listPath(
                        shareName=self.smb_share, 
                        path=(remote_smb_path + ntpath.sep + '*')
                    )
                except impacket.smbconnection.SessionError as err:
                    continue 
                # Remove dot names
                entries = [e for e in entries if e.get_longname() not in [".", ".."]]
                # Sort the entries ignoring case
                entries = sorted(entries, key=lambda x:x.get_longname().lower())
                
                for entry in entries:
                    if entry.is_directory():
                        callback(entry, path + ntpath.sep + entry.get_longname() + ntpath.sep, depth)
                    else:
                        callback(entry, path + ntpath.sep + entry.get_longname(), depth)

                # Next directories to explore
                for entry in entries:
                    if entry.is_directory():
                        next_directories_to_explore.append(path + ntpath.sep + entry.get_longname() + ntpath.sep)
            
            return next_directories_to_explore
        # 
        if callback is not None:
            depth = 0
            while len(paths) != 0:
                paths = recurse_action(
                    paths=paths,
                    depth=depth,
                    callback=callback
                )
                depth = depth + 1
        else:
            print("[!] SMBSession.find(), callback function cannot be None.")

    def get_file(self, path=None, keepRemotePath=False):
        """
        Retrieves a file from the specified path on the SMB share.

        This method attempts to retrieve a file from the given path within the currently connected SMB share.
        If the path points to a directory, it skips the retrieval. It handles file retrieval by creating a local
        file object and writing the contents of the remote file to it using the SMB client's getFile method.

        Parameters:
            path (str): The path of the file to retrieve. If None, uses the current smb_path.

        Returns:
            None
        """

        tmp_file_path = self.smb_cwd + ntpath.sep + path
        matches = self.smbClient.listPath(
            shareName=self.smb_share, 
            path=tmp_file_path
        )
        
        for entry in matches:
            if entry.is_directory():
                print("[>] Skipping '%s' because it is a directory." % tmp_file_path)
            else:
                try:
                    if ntpath.sep in path:
                        outputfile = ntpath.dirname(path) + ntpath.sep + entry.get_longname()
                    else:
                        outputfile = entry.get_longname()
                    f = LocalFileIO(
                        mode="wb", 
                        path=outputfile,
                        expected_size=entry.get_filesize(), 
                        debug=self.config.debug,
                        keepRemotePath=keepRemotePath
                    )
                    self.smbClient.getFile(
                        shareName=self.smb_share, 
                        pathName=tmp_file_path, 
                        callback=f.write
                    )
                    f.close()
                except (BrokenPipeError, KeyboardInterrupt) as e:
                    f.close()
                    print("\x1b[v\x1b[o\r[!] Interrupted.")
                    self.close_smb_session()
                    self.init_smb_session()
                        
        return None

    def get_file_recursively(self, path=None):
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
        
        def recurse_action(base_dir="", path=[]):
            remote_smb_path = base_dir + ntpath.sep.join(path)
            entries = self.smbClient.listPath(
                shareName=self.smb_share, 
                path=remote_smb_path + '\\*'
            )
            if len(entries) != 0:
                files = [entry for entry in entries if not entry.is_directory()]
                directories = [entry for entry in entries if entry.is_directory() and entry.get_longname() not in [".", ".."]]

                # Files
                if len(files) != 0:
                    print("[>] Retrieving files of '%s'" % remote_smb_path)
                for entry_file in files:
                    if not entry_file.is_directory():
                        f = LocalFileIO(
                            mode="wb",
                            path=remote_smb_path + ntpath.sep + entry_file.get_longname(), 
                            expected_size=entry_file.get_filesize(),
                            debug=self.config.debug
                        )
                        try:
                            self.smbClient.getFile(
                                shareName=self.smb_share, 
                                pathName=remote_smb_path + ntpath.sep + entry_file.get_longname(), 
                                callback=f.write
                            )
                            f.close()
                        except BrokenPipeError as err:
                            f.set_error(message="[bold red]Failed downloading '%s': %s" % (f.path, err))
                            f.close(remove=True)
                            break
                        except Exception as err:
                            f.set_error(message="[bold red]Failed downloading '%s': %s" % (f.path, err))
                            f.close(remove=True)
                
                # Directories
                for entry_directory in directories:
                    if entry_directory.is_directory():
                        recurse_action(
                            base_dir=self.smb_cwd, 
                            path=path+[entry_directory.get_longname()]
                        )                   
        # Entrypoint
        try:
            recurse_action(
                base_dir=self.smb_cwd, 
                path=[path]
            )
        except (BrokenPipeError, KeyboardInterrupt) as e:
            print("\x1b[v\x1b[o\r[!] Interrupted.")
            self.close_smb_session()
            self.init_smb_session()

    def get_entry(self, path=None):
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

    def info(self, share=True, server=True):
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
                print("[+] Server:")
                print("  ├─NetBIOS:")
                print("  │ ├─ NetBIOS Hostname ──────── : %s" % (self.smbClient.getServerName()))
                print("  │ └─ NetBIOS Domain ────────── : %s" % (self.smbClient.getServerDomain()))
                print("  ├─DNS:")
                print("  │ ├─ DNS Hostname ──────────── : %s" % (self.smbClient.getServerDNSHostName()))
                print("  │ └─ DNS Domain ────────────── : %s" % (self.smbClient.getServerDNSDomainName()))
                print("  ├─OS:")
                print("  │ ├─ OS Name ───────────────── : %s" % (self.smbClient.getServerOS()))
                print("  │ └─ OS Version ────────────── : %s.%s.%s" % (self.smbClient.getServerOSMajor(), self.smbClient.getServerOSMinor(), self.smbClient.getServerOSBuild()))
                print("  ├─Server:")
                print("  │ ├─ Signing Required ──────── : %s" % (self.smbClient.isSigningRequired()))
                print("  │ ├─ Login Required ────────── : %s" % (self.smbClient.isLoginRequired()))
                print("  │ ├─ Supports NTLMv2 ───────── : %s" % (self.smbClient.doesSupportNTLMv2()))
                MaxReadSize = self.smbClient.getIOCapabilities()["MaxReadSize"]
                print("  │ ├─ Max size of read chunk ── : %d bytes (%s)" % (MaxReadSize, b_filesize(MaxReadSize)))
                MaxWriteSize = self.smbClient.getIOCapabilities()["MaxWriteSize"]
                print("  │ └─ Max size of write chunk ─ : %d bytes (%s)" % (MaxWriteSize, b_filesize(MaxWriteSize)))
                print("  └─")
            else:
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
                print("  ├─Server:")
                print("  │ ├─ \x1b[94mSigning Required\x1b[0m \x1b[90m────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.isSigningRequired()))
                print("  │ ├─ \x1b[94mLogin Required\x1b[0m \x1b[90m──────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.isLoginRequired()))
                print("  │ ├─ \x1b[94mSupports NTLMv2\x1b[0m \x1b[90m─────────\x1b[0m : \x1b[93m%s\x1b[0m" % (self.smbClient.doesSupportNTLMv2()))
                MaxReadSize = self.smbClient.getIOCapabilities()["MaxReadSize"]
                print("  │ ├─ \x1b[94mMax size of read chunk\x1b[0m \x1b[90m──\x1b[0m : \x1b[93m%d bytes (%s)\x1b[0m" % (MaxReadSize, b_filesize(MaxReadSize)))
                MaxWriteSize = self.smbClient.getIOCapabilities()["MaxWriteSize"]
                print("  │ └─ \x1b[94mMax size of write chunk\x1b[0m \x1b[90m─\x1b[0m : \x1b[93m%d bytes (%s)\x1b[0m" % (MaxWriteSize, b_filesize(MaxWriteSize)))
                print("  └─")

        if share and self.smb_share is not None:
            share_name = self.available_shares.get(self.smb_share.lower(), "")["name"]
            share_comment = self.available_shares.get(self.smb_share.lower(), "")["comment"]
            share_type = self.available_shares.get(self.smb_share.lower(), "")["type"]
            share_type =', '.join([s.replace("STYPE_","") for s in share_type])
            share_rawtype = self.available_shares.get(self.smb_share.lower(), "")["rawtype"]
            if self.config.no_colors:
                print("\n[+] Share:")
                print("  ├─ Name ──────────── : %s" % (share_name))
                print("  ├─ Description ───── : %s" % (share_comment))
                print("  ├─ Type ──────────── : %s" % (share_type))
                print("  └─ Raw type value ── : %s" % (share_rawtype))
            else:
                print("\n[+] Share:")
                print("  ├─ \x1b[94mName\x1b[0m \x1b[90m────────────\x1b[0m : \x1b[93m%s\x1b[0m" % (share_name))
                print("  ├─ \x1b[94mDescription\x1b[0m \x1b[90m─────\x1b[0m : \x1b[93m%s\x1b[0m" % (share_comment))
                print("  ├─ \x1b[94mType\x1b[0m \x1b[90m────────────\x1b[0m : \x1b[93m%s\x1b[0m" % (share_type))
                print("  └─ \x1b[94mRaw type value\x1b[0m \x1b[90m──\x1b[0m : \x1b[93m%s\x1b[0m" % (share_rawtype))

    def list_contents(self, path=None):
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
        
        dest_path = [self.smb_cwd.rstrip(ntpath.sep),]
        if path is not None and len(path) > 0:
            dest_path.append(path.rstrip(ntpath.sep))
        dest_path.append('*')
        path = ntpath.sep.join(dest_path)

        contents = {}
        entries = self.smbClient.listPath(
            shareName=self.smb_share, 
            path=path
        )
        for entry in entries:
            contents[entry.get_longname()] = entry

        return contents

    def list_shares(self):
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
                        "comment": sharecomment
                    }
            else:
                print("[!] Error: SMBSession.smbClient is None.")

        return self.available_shares

    def mkdir(self, path=None):
        """
        Creates a directory at the specified path on the SMB share.

        This method takes a path and attempts to create the directory structure on the SMB share. If the path includes
        nested directories, it will create each directory in the sequence. If a directory already exists, it will skip
        the creation for that directory without raising an error.

        Args:
            path (str, optional): The full path of the directory to create on the SMB share. Defaults to None.

        Note:
            The path should use forward slashes ('/') which will be converted to backslashes (ntpath.sep) for SMB compatibility.
        """

        if path is not None:
            # Prepare path
            path = path.replace('/',ntpath.sep)
            if ntpath.sep in path:
                path = path.strip(ntpath.sep).split(ntpath.sep)
            else:
                path = [path]

            # Create each dir in the path
            for depth in range(1, len(path)+1):
                tmp_path = ntpath.sep.join(path[:depth])
                try:
                    self.smbClient.createDirectory(
                        shareName=self.smb_share, 
                        pathName=ntpath.normpath(self.smb_cwd + ntpath.sep + tmp_path + ntpath.sep)
                    )
                except impacket.smbconnection.SessionError as err:
                    if err.getErrorCode() == 0xc0000035:
                        # STATUS_OBJECT_NAME_COLLISION
                        # Remote directory already created, this is normal
                        # Src: https://github.com/fortra/impacket/blob/269ce69872f0e8f2188a80addb0c39fedfa6dcb8/impacket/nt_errors.py#L268C9-L268C19
                        pass
                    else:
                        print("[!] Failed to create directory '%s': %s" % (tmp_path, err))
                        if self.config.debug:
                            traceback.print_exc()
        else:
            pass

    def path_exists(self, path=None):
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
            path = path.replace('*','')
            try:
                contents = self.smbClient.listPath(
                    shareName=self.smb_share,
                    path=ntpath.normpath(self.smb_cwd + ntpath.sep + path + ntpath.sep)
                )
                return (len(contents) != 0)
            except Exception as e:
                return False
        else:
            return False
   
    def path_isdir(self, pathFromRoot=None):
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
            # Replace slashes if any
            path = pathFromRoot.replace('/', ntpath.sep)
            
            # Strip wildcards to avoid injections
            path = path.replace('*','')

            # Normalize path and strip leading backslash
            path = ntpath.normpath(path + ntpath.sep).lstrip(ntpath.sep)

            if path.strip() in ['', '.', '..']:
                # By defininition they exist on the filesystem
                return True
            else:
                try:
                    contents = self.smbClient.listPath(
                        shareName=self.smb_share,
                        path=path+'*'
                    )
                    # Filter on directories
                    contents = [
                        c for c in contents
                        if c.get_longname() == ntpath.basename(path) and c.is_directory()
                    ]
                    return (len(contents) != 0)
                except Exception as e:
                    return False
        else:
            return False

    def path_isfile(self, path=None):
        """
        Checks if the specified path is a file on the SMB share.

        This method determines if a given path corresponds to a file on the SMB share. It does this by listing the
        contents of the path and filtering for entries that match the basename of the path and are not marked as directories.

        Args:
            path (str, optional): The path to check on the SMB share. Defaults to None.

        Returns:
            bool: True if the path is a file, False otherwise or if an error occurs.
        """

        if path is not None:
            path = path.replace('*','')
            search_dir = ntpath.normpath(self.smb_cwd + ntpath.sep + path)
            search_dir = ntpath.dirname(search_dir) + ntpath.sep + '*'
            try:
                contents = self.smbClient.listPath(
                    shareName=self.smb_share,
                    path=search_dir
                )
                # Filter on files
                contents = [
                    c for c in contents
                    if c.get_longname() == ntpath.basename(path) and not c.is_directory()
                ]
                return (len(contents) != 0)
            except Exception as e:
                return False
        else:
            return False

    def ping_smb_session(self):
        """
        Tests the connectivity to the SMB server by sending an echo command.

        This method attempts to send an echo command to the SMB server to check if the session is still active.
        It updates the `connected` attribute of the class based on the success or failure of the echo command.

        Returns:
            bool: True if the echo command succeeds (indicating the session is active), False otherwise.
        """

        try:
            self.smbClient.getSMBServer().echo()
        except Exception as e:
            self.connected = False
        return self.connected

    def put_file(self, localpath=None):
        """
        Uploads a single file to the SMB share.

        This method takes a local file path, opens the file, and uploads it to the SMB share at the specified path.
        It handles exceptions such as broken pipe errors or keyboard interrupts by closing and reinitializing the SMB session.
        General exceptions are caught and logged, with a traceback provided if debugging is enabled.

        Args:
            localpath (str, optional): The local file path of the file to be uploaded. Defaults to None.
        """

        if os.path.exists(localpath):
            if os.path.isfile(localpath):
                try:
                    localfile = os.path.basename(localpath)
                    f = LocalFileIO(
                        mode="rb", 
                        path=localpath, 
                        debug=self.config.debug
                    )
                    self.smbClient.putFile(
                        shareName=self.smb_share, 
                        pathName=ntpath.normpath(self.smb_cwd + ntpath.sep + localfile + ntpath.sep), 
                        callback=f.read
                    )
                    f.close()
                except (BrokenPipeError, KeyboardInterrupt) as err:
                    print("[!] Interrupted.")
                    self.close_smb_session()
                    self.init_smb_session()
                except Exception as err:
                    print("[!] Failed to upload '%s': %s" % (localfile, err))
                    if self.config.debug:
                        traceback.print_exc()
            else:
                print("[!] The specified localpath is a directory. Use 'put -r <directory>' instead.")
        else:
            print("[!] The specified localpath does not exist.")

    def put_file_recursively(self, localpath=None):
        """
        Recursively uploads files from a specified local directory to the SMB share.

        This method walks through the given local directory and all its subdirectories, uploading each file to the
        corresponding directory structure on the SMB share. It first checks if the local path is a directory. If it is,
        it iterates over all files and directories within the local path, creating necessary directories on the SMB share
        and uploading files. If the local path is not a directory, it prints an error message.

        Args:
            localpath (str, optional): The local directory path from which files will be uploaded. Defaults to None.
        """

        if os.path.exists(localpath):
            if os.path.isfile(localpath):
                # Iterate over all files and directories within the local path
                local_files = {}
                for root, dirs, files in os.walk(localpath):
                    if len(files) != 0:
                        local_files[root] = files

                # Iterate over the found files
                for local_dir_path in sorted(local_files.keys()):
                    print("[>] Putting files of '%s'" % local_dir_path)

                    # Create remote directory
                    remote_dir_path = local_dir_path.replace(os.path.sep, ntpath.sep)
                    self.mkdir(
                        path=ntpath.normpath(self.smb_cwd + ntpath.sep + remote_dir_path + ntpath.sep)
                    )

                    for local_file_path in local_files[local_dir_path]:
                        try:
                            f = LocalFileIO(
                                mode="rb", 
                                path=local_dir_path + os.path.sep + local_file_path, 
                                debug=self.config.debug
                            )
                            self.smbClient.putFile(
                                shareName=self.smb_share, 
                                pathName=ntpath.normpath(self.smb_cwd + ntpath.sep + remote_dir_path + ntpath.sep + local_file_path), 
                                callback=f.read
                            )
                            f.close()

                        except BrokenPipeError as err:
                            f.set_error(message="[bold red]Failed uploading '%s': %s" % (f.path, err))
                            f.close(remove=True)
                            break
                        except Exception as err:
                            f.set_error(message="[bold red]Failed uploading '%s': %s" % (f.path, err))
                            f.close(remove=True)
                else:
                    print("[!] The specified localpath is a file. Use 'put <file>' instead.")
        else:
            print("[!] The specified localpath does not exist.")

    def rmdir(self, path=None):
        """
        Removes a directory from the SMB share at the specified path.

        This method attempts to delete a directory located at the given path on the SMB share. If the operation fails,
        it prints an error message indicating the failure and the reason. If debugging is enabled, it also prints
        the stack trace of the exception.

        Args:
            path (str, optional): The path of the directory to be removed on the SMB share. Defaults to None.
        """
        try:
            self.smbClient.deleteDirectory(
                shareName=self.smb_share, 
                pathName=ntpath.normpath(self.smb_cwd + ntpath.sep + path), 
            )
        except Exception as err:
            print("[!] Failed to remove directory '%s': %s" % (path, err))
            if self.config.debug:
                traceback.print_exc()

    def rm(self, path=None):
        """
        Removes a file from the SMB share at the specified path.

        This method attempts to delete a file located at the given path on the SMB share. If the operation fails,
        it prints an error message indicating the failure and the reason. If debugging is enabled, it also prints
        the stack trace of the exception.

        Args:
            path (str, optional): The path of the file to be removed on the SMB share. Defaults to None.
        """
        try:
            self.smbClient.deleteFile(
                shareName=self.smb_share, 
                pathName=ntpath.normpath(self.smb_cwd + ntpath.sep + path), 
            )
        except Exception as err:
            print("[!] Failed to remove file '%s': %s" % (path, err))
            if self.config.debug:
                traceback.print_exc()

    def tree(self, path=None):
        """
        Recursively lists the directory structure of the SMB share starting from the specified path.

        This function prints a visual representation of the directory tree of the remote SMB share. It uses
        recursion to navigate through directories and lists all files and subdirectories in each directory.
        The output is color-coded and formatted to enhance readability, with directories highlighted in cyan.

        Args:
            path (str, optional): The starting path on the SMB share from which to begin listing the tree.
                                  Defaults to the root of the current share.
        """
        
        def recurse_action(base_dir="", path=[], prompt=[]):
            bars = ["│   ", "├── ", "└── "]

            remote_smb_path = ntpath.normpath(base_dir + ntpath.sep + ntpath.sep.join(path))

            entries = []
            try:
                entries = self.smbClient.listPath(
                    shareName=self.smb_share, 
                    path=remote_smb_path+'\\*'
                )
            except impacket.smbconnection.SessionError as err:
                code, const, text = err.getErrorCode(), err.getErrorString()[0], err.getErrorString()[1]
                errmsg = "Error 0x%08x (%s): %s" % (code, const, text)
                if self.config.no_colors:
                    print("%s%s" % (''.join(prompt+[bars[2]]), errmsg))
                else:
                    print("%s\x1b[1;91m%s\x1b[0m" % (''.join(prompt+[bars[2]]), errmsg))
                return 

            entries = [e for e in entries if e.get_longname() not in [".", ".."]]
            entries = sorted(entries, key=lambda x:x.get_longname())

            # 
            if len(entries) > 1:
                index = 0
                for entry in entries:
                    index += 1
                    # This is the first entry 
                    if index == 0:
                        if entry.is_directory():
                            if self.config.no_colors:
                                print("%s%s\\" % (''.join(prompt+[bars[1]]), entry.get_longname()))
                            else:
                                print("%s\x1b[1;96m%s\x1b[0m\\" % (''.join(prompt+[bars[1]]), entry.get_longname()))
                            recurse_action(
                                base_dir=base_dir, 
                                path=path+[entry.get_longname()],
                                prompt=prompt+["│   "]
                            )
                        else:
                            if self.config.no_colors:
                                print("%s%s" % (''.join(prompt+[bars[1]]), entry.get_longname()))
                            else:
                                print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[1]]), entry.get_longname()))

                    # This is the last entry
                    elif index == len(entries):
                        if entry.is_directory():
                            if self.config.no_colors:
                                print("%s%s\\" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                            else:
                                print("%s\x1b[1;96m%s\x1b[0m\\" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                            recurse_action(
                                base_dir=base_dir, 
                                path=path+[entry.get_longname()],
                                prompt=prompt+["    "]
                            )
                        else:
                            if self.config.no_colors:
                                print("%s%s" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                            else:
                                print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                        
                    # These are entries in the middle
                    else:
                        if entry.is_directory():
                            if self.config.no_colors:
                                print("%s%s\\" % (''.join(prompt+[bars[1]]), entry.get_longname()))
                            else:
                                print("%s\x1b[1;96m%s\x1b[0m\\" % (''.join(prompt+[bars[1]]), entry.get_longname()))
                            recurse_action(
                                base_dir=base_dir, 
                                path=path+[entry.get_longname()],
                                prompt=prompt+["│   "]
                            )
                        else:
                            if self.config.no_colors:
                                print("%s%s" % (''.join(prompt+[bars[1]]), entry.get_longname()))
                            else:
                                print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[1]]), entry.get_longname()))

            # 
            elif len(entries) == 1:
                entry = entries[0]
                if entry.is_directory():
                    if self.config.no_colors:
                        print("%s%s\\" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                    else:
                        print("%s\x1b[1;96m%s\x1b[0m\\" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                    recurse_action(
                        base_dir=base_dir, 
                        path=path+[entry.get_longname()],
                        prompt=prompt+["    "]
                    )
                else:
                    if self.config.no_colors:
                        print("%s%s" % (''.join(prompt+[bars[2]]), entry.get_longname()))
                    else:
                        print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[2]]), entry.get_longname()))

        # Entrypoint
        try:
            if self.config.no_colors:
                print("%s\\" % path)
            else:
                print("\x1b[1;96m%s\x1b[0m\\" % path)
            recurse_action(
                base_dir=self.smb_cwd, 
                path=[path],
                prompt=[""]
            )
        except (BrokenPipeError, KeyboardInterrupt) as e:
            print("[!] Interrupted.")
            self.close_smb_session()
            self.init_smb_session()

    # Setter / Getter

    def set_share(self, shareName):
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
            else:
                print("[!] Could not set share '%s', it does not exist remotely." % shareName)

    def set_cwd(self, path=None):
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
            if '/' in path:
                path = path.replace('/', ntpath.sep)

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
            path = re.sub(r'\\+', r'\\', path)

            if path in ["", ".", ".."]:
                self.smb_cwd = ""
            else:
                if self.path_isdir(pathFromRoot=path.strip(ntpath.sep)):
                    # Path exists on the remote 
                    self.smb_cwd = ntpath.normpath(path)
                else:
                    # Path does not exists or is not a directory on the remote 
                    print("[!] Remote directory '%s' does not exist." % path)
