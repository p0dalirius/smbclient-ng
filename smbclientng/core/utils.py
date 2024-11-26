#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : utils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024

from __future__ import annotations
import datetime
import fnmatch
import ntpath
import os
import re
import socket
import stat
from impacket.smbconnection import SessionError
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional
    from impacket.smb import SharedFile
    from smbclientng.core.Config import Config
    from smbclientng.core.SMBSession import SMBSession

def parse_lm_nt_hashes(lm_nt_hashes_string: str) -> tuple[str, str]:
    """
    Parse the input string containing LM and NT hash values and return them separately.

    This function takes a string containing LM and NT hash values, typically separated by a colon (:).
    It returns the LM and NT hash values as separate strings. If only one hash value is provided, it is
    assumed to be the NT hash and the LM hash is set to its default value. If no valid hash values are
    found, both return values are empty strings.

    Args:
        lm_nt_hashes_string (str): A string containing LM and NT hash values separated by a colon.

    Returns:
        tuple: A tuple containing two strings (lm_hash_value, nt_hash_value).
               - lm_hash_value: The LM hash value or its default if not provided.
               - nt_hash_value: The NT hash value or its default if not provided.
    
    Extracted from p0dalirius/sectools library
    Src: https://github.com/p0dalirius/sectools/blob/7bb3f5cb7815ad4d4845713c8739e2e2b0ea4e75/sectools/windows/crypto.py#L11-L24
    """

    lm_hash_value, nt_hash_value = "", ""
    if lm_nt_hashes_string is not None:
        matched = re.match("([0-9a-f]{32})?(:)?([0-9a-f]{32})?", lm_nt_hashes_string.strip().lower())
        m_lm_hash, m_sep, m_nt_hash = matched.groups()
        if m_lm_hash is None and m_sep is None and m_nt_hash is None:
            lm_hash_value, nt_hash_value = "", ""
        elif m_lm_hash is None and m_nt_hash is not None:
            lm_hash_value = "aad3b435b51404eeaad3b435b51404ee"
            nt_hash_value = m_nt_hash
        elif m_lm_hash is not None and m_nt_hash is None:
            lm_hash_value = m_lm_hash
            nt_hash_value = "31d6cfe0d16ae931b73c59d7e0c089c0"
    return lm_hash_value, nt_hash_value


def b_filesize(l: int) -> str:
    """
    Convert a file size from bytes to a more readable format using the largest appropriate unit.

    This function takes an integer representing a file size in bytes and converts it to a human-readable
    string using the largest appropriate unit from bytes (B) to petabytes (PB). The result is rounded to
    two decimal places.

    Args:
        l (int): The file size in bytes.

    Returns:
        str: A string representing the file size in a more readable format, including the appropriate unit.
    """

    units = ['B','kB','MB','GB','TB','PB']
    for k in range(len(units)):
        if l < (1024**(k+1)):
            break
    return "%4.2f %s" % (round(l/(1024**(k)),2), units[k])


def unix_permissions(entryname: str) -> str:
    """
    Generate a string representing the Unix-style permissions for a given file or directory.

    This function uses the os.lstat() method to retrieve the status of the specified file or directory,
    then constructs a string that represents the Unix-style permissions based on the mode of the file.

    Args:
        entryname (str): The path to the file or directory for which permissions are being determined.

    Returns:
        str: A string of length 10 representing the Unix-style permissions (e.g., '-rwxr-xr--').
             The first character is either 'd' (directory), '-' (not a directory), followed by
             three groups of 'r', 'w', 'x' (read, write, execute permissions) for owner, group,
             and others respectively.
    """

    mode = os.lstat(entryname).st_mode
    permissions = []

    permissions.append('d' if stat.S_ISDIR(mode) else '-')

    permissions.append('r' if mode & stat.S_IRUSR else '-')
    permissions.append('w' if mode & stat.S_IWUSR else '-')
    permissions.append('x' if mode & stat.S_IXUSR else '-')

    permissions.append('r' if mode & stat.S_IRGRP else '-')
    permissions.append('w' if mode & stat.S_IWGRP else '-')
    permissions.append('x' if mode & stat.S_IXGRP else '-')

    permissions.append('r' if mode & stat.S_IROTH else '-')
    permissions.append('w' if mode & stat.S_IWOTH else '-')
    permissions.append('x' if mode & stat.S_IXOTH else '-')

    return ''.join(permissions)


def STYPE_MASK(stype_value: int) -> list[str]:
    """
    Extracts the share type flags from a given share type value.

    This function uses bitwise operations to determine which share type flags are set in the provided `stype_value`.
    It checks against known share type flags and returns a list of the flags that are set.

    Parameters:
        stype_value (int): The share type value to analyze, typically obtained from SMB share properties.

    Returns:
        list: A list of strings, where each string represents a share type flag that is set in the input value.
    """

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
    flags : list[str] = []
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


def windows_ls_entry(entry: SharedFile, config: Config, pathToPrint: Optional[str] =None):
    """
    This function generates a metadata string based on the attributes of the provided entry object.
    
    Parameters:
        entry (object): An object representing a file or directory entry.

    Returns:
        str: A string representing the metadata of the entry, including attributes like directory, archive, compressed, hidden, normal, readonly, system, and temporary.
    """
    
    if pathToPrint is not None:
        pathToPrint = pathToPrint + ntpath.sep + entry.get_longname()
    else:
        pathToPrint = entry.get_longname()

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
    
    output_str = ""
    if entry.is_directory():
        if config.no_colors:
            output_str = ("%s %10s  %s  %s\\" % (meta_string, size_str, date_str, pathToPrint))
        else:
            output_str = ("%s %10s  %s  \x1b[1;96m%s\x1b[0m\\" % (meta_string, size_str, date_str, pathToPrint))
    else:
        if config.no_colors:
            output_str = ("%s %10s  %s  %s" % (meta_string, size_str, date_str, pathToPrint))
        else:
            output_str = ("%s %10s  %s  \x1b[1m%s\x1b[0m" % (meta_string, size_str, date_str, pathToPrint))

    return output_str


def local_tree(path: str, config: Config):
    """
    This function recursively lists the contents of a directory in a tree-like format.

    Parameters:
        path (str): The path to the directory to list.
        config (object): Configuration settings which may affect the output, such as whether to use colors.

    Returns:
        None: This function does not return anything but prints the directory tree to the console.
    """

    def recurse_action(base_dir="", path=[], prompt=[]):
        bars = ["│   ", "├── ", "└── "]

        local_path = os.path.normpath(base_dir + os.path.sep + os.path.sep.join(path) + os.path.sep)

        entries = []
        try:
            entries = os.listdir(local_path)
        except Exception as err:
            if config.no_colors:
                print("%s%s" % (''.join(prompt+[bars[2]]), err))
            else:
                print("%s\x1b[1;91m%s\x1b[0m" % (''.join(prompt+[bars[2]]), err))
            return 

        entries = sorted(entries)

        # 
        if len(entries) > 1:
            index = 0
            for entry in entries:
                index += 1
                # This is the first entry 
                if index == 0:
                    if os.path.isdir(local_path + os.path.sep + entry):
                        if config.no_colors:
                            print("%s%s%s" % (''.join(prompt+[bars[1]]), entry, os.path.sep))
                        else:
                            print("%s\x1b[1;96m%s\x1b[0m%s" % (''.join(prompt+[bars[1]]), entry, os.path.sep))
                        recurse_action(
                            base_dir=base_dir, 
                            path=path+[entry],
                            prompt=prompt+["│   "]
                        )
                    else:
                        if config.no_colors:
                            print("%s%s" % (''.join(prompt+[bars[1]]), entry))
                        else:
                            print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[1]]), entry))

                # This is the last entry
                elif index == len(entries):
                    if os.path.isdir(local_path + os.path.sep + entry):
                        if config.no_colors:
                            print("%s%s%s" % (''.join(prompt+[bars[2]]), entry, os.path.sep))
                        else:
                            print("%s\x1b[1;96m%s\x1b[0m%s" % (''.join(prompt+[bars[2]]), entry, os.path.sep))
                        recurse_action(
                            base_dir=base_dir, 
                            path=path+[entry],
                            prompt=prompt+["    "]
                        )
                    else:
                        if config.no_colors:
                            print("%s%s" % (''.join(prompt+[bars[2]]), entry))
                        else:
                            print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[2]]), entry))
                    
                # These are entries in the middle
                else:
                    if os.path.isdir(local_path + os.path.sep + entry):
                        if config.no_colors:
                            print("%s%s%s" % (''.join(prompt+[bars[1]]), entry, os.path.sep))
                        else:
                            print("%s\x1b[1;96m%s\x1b[0m%s" % (''.join(prompt+[bars[1]]), entry, os.path.sep))
                        recurse_action(
                            base_dir=base_dir, 
                            path=path+[entry],
                            prompt=prompt+["│   "]
                        )
                    else:
                        if config.no_colors:
                            print("%s%s" % (''.join(prompt+[bars[1]]), entry))
                        else:
                            print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[1]]), entry))

        # 
        elif len(entries) == 1:
            entry = entries[0]
            if os.path.isdir(local_path + os.path.sep + entry):
                if config.no_colors:
                    print("%s%s%s" % (''.join(prompt+[bars[2]]), entry, os.path.sep))
                else:
                    print("%s\x1b[1;96m%s\x1b[0m%s" % (''.join(prompt+[bars[2]]), entry, os.path.sep))
                recurse_action(
                    base_dir=base_dir, 
                    path=path+[entry],
                    prompt=prompt+["    "]
                )
            else:
                if config.no_colors:
                    print("%s%s" % (''.join(prompt+[bars[2]]), entry))
                else:
                    print("%s\x1b[1m%s\x1b[0m" % (''.join(prompt+[bars[2]]), entry))

    # Entrypoint
    try:
        if config.no_colors:
            print("%s%s" % (path, os.path.sep))
        else:
            print("\x1b[1;96m%s\x1b[0m%s" % (path, os.path.sep))
        recurse_action(
            base_dir=os.getcwd(),
            path=[path],
            prompt=[""]
        )
    except (BrokenPipeError, KeyboardInterrupt) as e:
        print("[!] Interrupted.")


def resolve_local_files(arguments: list[str]) -> list[str]:
    """
    Resolves local file paths based on the provided arguments.

    This function takes a list of arguments, which can include wildcard patterns, and resolves them to actual file paths.
    If an argument contains a wildcard ('*'), it attempts to match files in the specified directory against the pattern.
    If the argument does not contain a wildcard, it is added to the list of resolved files as is.

    Args:
        arguments (list): A list of file path arguments, which may include wildcard patterns.

    Returns:
        list: A list of resolved file paths that match the provided arguments.
    """

    resolved_files: list[str] = []
    for arg in arguments:
        if '*' in arg:
            try:
                path = os.path.dirname(arg) or '.'
                pattern = os.path.basename(arg)
                for entry in os.listdir(path):
                    if fnmatch.fnmatch(entry, pattern):
                        resolved_files.append(os.path.join(path, entry))
            except FileNotFoundError as err:
                pass
        else:
            resolved_files.append(arg)
    resolved_files = sorted(list(set(resolved_files)))
    return resolved_files


def resolve_remote_files(smbSession: SMBSession, arguments: list[str]) -> list[str]:
    """
    Resolves remote file paths based on the provided arguments using an SMB session.

    This function takes a list of arguments, which can include wildcard patterns, and resolves them to actual remote file paths.
    If an argument contains a wildcard ('*'), it attempts to match files in the specified remote directory against the pattern.
    If the argument does not contain a wildcard, it is added to the list of resolved files as is.

    Args:
        smbsession (SMBSession): The SMB session through which to access the files.
        arguments (list): A list of file path arguments, which may include wildcard patterns.

    Returns:
        list: A list of resolved remote file paths that match the provided arguments.
    """

    DEBUG = False

    resolved_pathFromRoot_files = []
    for arg in arguments:
        # Parse argument values
        if DEBUG: print(f"[debug] Parsing argument '{arg}'")

        # Handle wildcard '*'
        if arg == '*':
            if DEBUG: print("[debug] |--> Argument is a wildcard")
            # Find all the remote files in current directory
            cwd = smbSession.smb_cwd or ntpath.sep  # Ensure cwd is not empty
            search_path = ntpath.join(cwd, '*')
            contents = smbSession.smbClient.listPath(
                shareName=smbSession.smb_share,
                path=search_path
            )
            contents = [e for e in contents if e.get_longname() not in ['.', '..']]
            for entry in contents:
                # Construct absolute path starting from the root
                resolved_path = ntpath.normpath(ntpath.join(ntpath.sep, cwd, entry.get_longname()))
                resolved_pathFromRoot_files.append(resolved_path)

        # Handle relative paths
        elif not arg.startswith(ntpath.sep):
            # Get the full path relative to the current working directory
            full_arg_path = ntpath.join(smbSession.smb_cwd, arg)
            if '*' in arg:
                if DEBUG: print("[debug] |--> Argument is a relative path with wildcard")
                # Get the directory and pattern
                dir_name = ntpath.dirname(full_arg_path) or smbSession.smb_cwd
                pattern = ntpath.basename(arg)
                search_path = ntpath.join(dir_name, '*')
                contents = smbSession.smbClient.listPath(
                    shareName=smbSession.smb_share,
                    path=search_path
                )
                contents = [e for e in contents if e.get_longname() not in ['.', '..']]
                for entry in contents:
                    if fnmatch.fnmatch(entry.get_longname(), pattern):
                        resolved_path = ntpath.normpath(ntpath.join(ntpath.sep, dir_name, entry.get_longname()))
                        resolved_pathFromRoot_files.append(resolved_path)
            else:
                if DEBUG: print("[debug] |--> Argument is a relative path")
                resolved_path = ntpath.normpath(ntpath.join(ntpath.sep, smbSession.smb_cwd, arg))
                resolved_pathFromRoot_files.append(resolved_path)

        # Handle absolute paths
        elif arg.startswith(ntpath.sep):
            if '*' in arg:
                if DEBUG: print("[debug] |--> Argument is an absolute path with wildcard")
                dir_name = ntpath.dirname(arg) or ntpath.sep
                pattern = ntpath.basename(arg)
                search_path = ntpath.join(dir_name, '*')
                contents = smbSession.smbClient.listPath(
                    shareName=smbSession.smb_share,
                    path=search_path
                )
                contents = [e for e in contents if e.get_longname() not in ['.', '..']]
                for entry in contents:
                    if fnmatch.fnmatch(entry.get_longname(), pattern):
                        resolved_path = ntpath.normpath(ntpath.join(dir_name, entry.get_longname()))
                        resolved_pathFromRoot_files.append(resolved_path)
            else:
                if DEBUG: print("[debug] |--> Argument is an absolute path")
                resolved_path = ntpath.normpath(arg)
                resolved_pathFromRoot_files.append(resolved_path)

    # Remove duplicates and sort
    resolved_pathFromRoot_files = sorted(set(resolved_pathFromRoot_files))

    return resolved_pathFromRoot_files


def is_port_open(target: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
    """
    Check if a specific port on a target host is open.

    This function attempts to establish a TCP connection to the specified port on the target host.
    If the connection is successful, it indicates that the port is open. If the connection fails,
    it returns the error message.

    Args:
        target (str): The hostname or IP address of the target host.
        port (int): The port number to check.
        timeout (float): The timeout in seconds for the connection attempt. Default is 1.0 second.

    Returns:
        bool, str: True if the port is open, otherwise False and error message.
    """
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            return True, None
    except Exception as e:
        return False, str(e)

    
def smb_entry_iterator(smb_client, smb_share: str, start_paths: list[str], exclusion_rules=[], max_depth: Optional[int] = None, min_depth: int = 0, current_depth: int = 0, filters: Optional[dict] = None):
    """
    Iterates over SMB entries by traversing directories in a depth-first manner.

    This function recursively traverses through directories on an SMB share, yielding
    each entry found along with its full path, current depth, and information on whether
    it is the last entry in its directory.

    Args:
        smb_client: The SMB client instance used to interact with the remote share.
        smb_share (str): The name of the SMB share being traversed.
        start_paths (list): A list of initial paths to start traversing from.
        exclusion_rules (list): Rules to exclude certain directories from traversal.
        max_depth (int, optional): The maximum depth to traverse. If None, no depth limit is applied.
        current_depth (int): The current depth of traversal in the directory hierarchy.

    Yields:
        tuple: A tuple containing:
            - entry: The current SMB entry object (e.g., file or directory).
            - fullpath (str): The full path to the current entry.
            - depth (int): The current depth level of the entry within the traversal.
            - is_last_entry (bool): True if the entry is the last within its directory, False otherwise.
    """
    def entry_matches_filters(entry, filters) -> bool:
        """
        Checks if an entry matches the provided filters.

        Args:
            entry: The SMB entry to check.
            filters (dict): Dictionary of filters.

        Returns:
            bool: True if the entry matches the filters, False otherwise.
        """
        # Filter by type
        entry_type = 'd' if entry.is_directory() else 'f'
        if 'type' in filters and filters['type'] != entry_type:
            return False

        # Filter by name (case-sensitive)
        if 'name' in filters:
            name_patterns = filters['name']
            if isinstance(name_patterns, str):
                name_patterns = [name_patterns]
            if not any(fnmatch.fnmatchcase(entry_name, pattern) for pattern in name_patterns):
                return False

        # Filter by name (case-insensitive)
        if 'iname' in filters:
            iname_patterns = filters['iname']
            if isinstance(iname_patterns, str):
                iname_patterns = [iname_patterns]
            entry_name_lower = entry_name.lower()
            if not any(fnmatch.fnmatch(entry_name_lower, pattern.lower()) for pattern in iname_patterns):
                return False

        # Filter by size
        if 'size' in filters and not entry.is_directory():
            size_filter = filters['size']
            size = entry.get_filesize()
            if not size_matches_filter(size, size_filter):
                return False

        return True

    def size_matches_filter(size: int, size_filter: str) -> bool:
        """
        Checks if a size matches the size filter.

        Args:
            size (int): The size in bytes.
            size_filter (str): The size filter string (e.g., '+1M', '-500K').

        Returns:
            bool: True if the size matches the filter, False otherwise.
        """
        import re

        match = re.match(r'([+-]?)(\d+)([BKMGTP]?)', size_filter, re.IGNORECASE)
        if not match:
            return False

        operator, number, unit = match.groups()
        number = int(number)
        unit_multipliers = {'': 1, 'B': 1, 'K': 1024, 'M': 1024**2,
                            'G': 1024**3, 'T': 1024**4, 'P': 1024**5}
        multiplier = unit_multipliers.get(unit.upper(), 1)
        threshold = number * multiplier

        if operator == '+':
            return size >= threshold
        elif operator == '-':
            return size <= threshold
        else:
            return size == threshold

    # Entrypoint
    for base_path in start_paths:
        try:
            entries = smb_client.listPath(
                shareName=smb_share,
                path=ntpath.join(base_path, '*')
            )

            entries = [e for e in entries if e.get_longname() not in ['.', '..']]
            entries.sort(key=lambda e: (not e.is_directory(), e.get_longname().lower()))

            entries_count = len(entries)
            for index, entry in enumerate(entries):
                # Determine if this is the last entry in the directory
                is_last_entry = (index == entries_count - 1)
                entry_name = entry.get_longname()
                fullpath = ntpath.join(base_path, entry_name)

                # Apply exclusion rules
                exclude = False
                for rule in exclusion_rules:
                    dirname = rule['dirname']
                    depth = rule.get('depth', -1)
                    case_sensitive = rule.get('case_sensitive', True)
                    match_name = entry_name if case_sensitive else entry_name.lower()
                    match_dirname = dirname if case_sensitive else dirname.lower()

                    if match_name == match_dirname and (depth == -1 or current_depth <= depth):
                        exclude = True
                        break

                if exclude:
                    continue

                # Apply depth filtering
                if (max_depth is not None and current_depth > max_depth) or current_depth < min_depth:
                    continue

                # Recursion for directories
                if entry.is_directory():
                    yield_dir = True
                    if filters:
                        # Check if 'type' filter is specified
                        if 'type' in filters:
                            if filters['type'] == 'd':
                                yield_dir = True
                            else:
                                yield_dir = False
                        else:
                            # Filters are applied, but 'type' is not specified
                            # Assume filters are for files, prevent directory from being yielded
                            yield_dir = False
                    else:
                        # No filters, yield directories
                        yield_dir = True

                    # Yield the directory if it matches the criteria
                    if yield_dir:
                        yield entry, fullpath, current_depth, is_last_entry

                    if max_depth is None or current_depth < max_depth:
                        yield from smb_entry_iterator(
                            smb_client=smb_client,
                            smb_share=smb_share,
                            start_paths=[fullpath],
                            exclusion_rules=exclusion_rules,
                            max_depth=max_depth,
                            min_depth=min_depth,
                            current_depth=current_depth + 1,
                            filters=filters
                        )
                else:
                    # Apply filters
                    if filters:
                        if not entry_matches_filters(entry, filters):
                            continue

                    # Yield the file
                    yield entry, fullpath, current_depth, is_last_entry

        except SessionError as err:
            message = f"{err}. Base path: {base_path}"
            print("[\x1b[1;91merror\x1b[0m] %s" % message)
            continue
