#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : metadata.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import traceback
from smbclientng.utils.decorator import command_arguments_required, smb_share_is_set, active_smb_connection_needed
from smbclientng.utils import resolve_remote_files
import datetime
from smbclientng.utils.utils import b_filesize
import ntpath


HELP = {
    "description": [
        "Get all metadata about a remote file.",
        "Syntax: 'metadata <remote_file_path>'"
    ], 
    "subcommands": [],
    "autocomplete": []
}


@command_arguments_required
@smb_share_is_set
@active_smb_connection_needed
def command_metadata(self, arguments: list[str], command: str):
    # Command arguments required   : Yes
    # Active SMB connection needed : Yes
    # SMB share needed             : Yes

    arguments = resolve_remote_files(self.sessionsManager.current_session, arguments)

    smbClient = self.sessionsManager.current_session.smbClient
    sharename = self.sessionsManager.current_session.smb_share
    
    for path_to_file in arguments:
        entry = self.sessionsManager.current_session.get_entry(path_to_file)

        if entry is None:
            self.logger.error(f"File {path_to_file} not found")
            continue

        # Get file attributes   
        try:
            uncPath = r'\\%s\%s\%s' % (self.sessionsManager.current_session.host, self.sessionsManager.current_session.smb_share, path_to_file.lstrip(ntpath.sep))

            self.logger.print("[+] Metadata of '%s'" % uncPath)
            if self.config.no_colors:
                self.logger.print("  ├─ %-4s: %s" % ("Name", entry.get_shortname()))
                self.logger.print("  ├─ %-4s: %s" % ("Path", uncPath))
            else:
                self.logger.print("  ├─ \x1b[94m%-4s\x1b[0m: \x1b[93m%s\x1b[0m" % ("Name", entry.get_shortname()))
                self.logger.print("  ├─ \x1b[94m%-4s\x1b[0m: \x1b[93m%s\x1b[0m" % ("Path", uncPath))

            self.logger.print("  ├─ [+] General information")
            if entry.is_directory():
                if self.config.no_colors:
                    self.logger.print("  │    ├─ %-10s: %s" % ("Type", "📁 Directory"))
                else:
                    self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m📁 Directory\x1b[0m" % ("Type"))
                contents = []
                try:
                    contents = smbClient.listPath(shareName=sharename, path=ntpath.join(entry.get_longname(), "*"))
                    nb_files = 0
                    nb_directories = 0
                    for child_entry in contents:
                        if child_entry.is_directory():
                            nb_directories += 1
                        else:
                            nb_files += 1   
                    if self.config.no_colors:
                        self.logger.print("  │    ├─ %-10s: %d files, %d directories" % ("Contents", nb_files, nb_directories))
                    else:
                        self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m%d files, %d directories\x1b[0m" % ("Contents", nb_files, nb_directories))
                except Exception as err:
                    if self.config.no_colors:
                        self.logger.print("  │    ├─ %-10s: ? files, ? directories" % ("Contents"))
                    else:
                        self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m? files, ? directories\x1b[0m" % ("Contents"))
            else:
                if self.config.no_colors:
                    self.logger.print("  │    ├─ %-10s: %s" % ("Type", "📄 File"))
                    self.logger.print("  │    ├─ %-10s: %s" % ("Size", entry.get_filesize(), b_filesize(entry.get_filesize())))
                else:
                    self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m📄 File\x1b[0m" % ("Type"))
                    self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m%d (%s)\x1b[0m" % ("Size", entry.get_filesize(), b_filesize(entry.get_filesize())))

            attributes_string = []
            attributes_string += (["Directory"] if entry.is_directory() else [])
            attributes_string += (["Archive"] if entry.is_archive() else [])
            attributes_string += (["Compressed"] if entry.is_compressed() else [])
            attributes_string += (["Hidden"] if entry.is_hidden() else [])
            attributes_string += (["Normal"] if entry.is_normal() else [])
            attributes_string += (["ReadOnly"] if entry.is_readonly() else [])
            attributes_string += (["System"] if entry.is_system() else [])
            attributes_string += (["Temporary"] if entry.is_temporary() else [])
            attributes_string = sorted(list(set(attributes_string)))
            if self.config.no_colors:
                self.logger.print("  │    ├─ %-10s: %d %s" % ("Attributes", entry.get_attributes(), attributes_string))
            else:
                self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m%d\x1b[0m (\x1b[93m%s\x1b[0m)" % ("Attributes", entry.get_attributes(), '\x1b[0m, \x1b[93m'.join(attributes_string)))
            self.logger.print("  │    └───")

            self.logger.print("  ├─ [+] Timestamps")
            Created = entry.get_ctime_epoch()
            try:
                Created = datetime.datetime.fromtimestamp(Created).strftime("%Y-%m-%d %H:%M:%S")
            except Exception as err:
                pass

            if self.config.no_colors:
                self.logger.print("  │    ├─ %-10s: %s" % ("Created", Created))
            else:
                self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m%s\x1b[0m" % ("Created", Created))

            Accessed = entry.get_atime_epoch()
            try:
                Accessed = datetime.datetime.fromtimestamp(Accessed).strftime("%Y-%m-%d %H:%M:%S")
            except Exception as err:
                pass    
            if self.config.no_colors:
                self.logger.print("  │    ├─ %-10s: %s" % ("Accessed", Accessed))
            else:
                self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m%s\x1b[0m" % ("Accessed", Accessed))

            Modified = entry.get_mtime_epoch()
            try:
                Modified = datetime.datetime.fromtimestamp(Modified).strftime("%Y-%m-%d %H:%M:%S")
            except Exception as err:
                pass
            if self.config.no_colors:
                self.logger.print("  │    ├─ %-10s: %s" % ("Modified", Modified))
            else:
                self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m%s\x1b[0m" % ("Modified", Modified))
            self.logger.print("  │    └───")

            # Get alternate data streams
            ads = self.sessionsManager.current_session.get_alternate_data_streams(path_to_file)

            self.logger.print("  ├─ [+] Alternate Data Streams")
            if self.config.no_colors:
                self.logger.print("  │    ├─ %-10s: %s" % ("Alternate Data Streams", len(ads)))
            else:
                self.logger.print("  │    ├─ \x1b[94m%-10s\x1b[0m: \x1b[93m%s\x1b[0m" % ("Alternate Data Streams", len(ads)))
            for i, ad in enumerate(ads):
                if self.config.no_colors:
                    self.logger.print("  │    ├─ #%02d: %s:%s (%s)" % (i+1, entry.get_shortname(), ad["Name"], b_filesize(ad["Size"])))
                else:
                    self.logger.print("  │    ├─ \x1b[94m#%02d\x1b[0m: \x1b[93m%s:%s\x1b[0m (%s)" % (i+1, entry.get_shortname(), ad["Name"], b_filesize(ad["Size"])))
            self.logger.print("  │    └───")
            self.logger.print("  └───")

        except Exception as err:
            traceback.print_exc()
