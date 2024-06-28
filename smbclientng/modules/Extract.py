#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Extract.py
# Author             : Podalirius (@podalirius_)
# Date created       : 23 may 2024

import os
import pefile
import shutil
import tempfile
import zipfile
from smbclientng.core.Module import Module
from smbclientng.core.ModuleArgumentParser import ModuleArgumentParser


def pe_get_version(pathtopefile):
    data = {"FileVersion": "", "ProductVersion": ""}
    p = pefile.PE(pathtopefile)
    data["FileVersion"] = "%d.%d.%d.%d" % (
        (p.VS_FIXEDFILEINFO[0].FileVersionMS >> 16) & 0xffff, 
        (p.VS_FIXEDFILEINFO[0].FileVersionMS >> 0) & 0xffff, 
        (p.VS_FIXEDFILEINFO[0].FileVersionLS >> 16) & 0xffff, 
        (p.VS_FIXEDFILEINFO[0].FileVersionLS >> 0) & 0xffff
    )
    data["ProductVersion"] = "%d.%d.%d.%d" % (
        (p.VS_FIXEDFILEINFO[0].ProductVersionMS >> 16) & 0xffff, 
        (p.VS_FIXEDFILEINFO[0].ProductVersionMS >> 0) & 0xff, 
        (p.VS_FIXEDFILEINFO[0].ProductVersionLS >> 16) & 0xffff, 
        (p.VS_FIXEDFILEINFO[0].ProductVersionLS >> 0) & 0xffff
    )
    return data


class Extract(Module):

    name = "extract"
    description = "Extracts interesting files of a remote system."

    def parseArgs(self, arguments):
        """
        Parses the command line arguments provided to the module.

        This method initializes the argument parser with the module's name and description, and defines all the necessary arguments that the module accepts. It then parses the provided command line arguments based on these definitions.

        Args:
            arguments (str): A string of command line arguments.

        Returns:
            ModuleArgumentParser.Namespace | None: The parsed arguments as a Namespace object if successful, None if there are no arguments or help is requested.
        """

        parser = ModuleArgumentParser(prog=self.name, description=self.description)

        parser.add_argument("targets", metavar="target", type=str, nargs="*", default=[], help="The path(s) to the file(s) to extract.")

        parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose mode.")
        parser.add_argument("-o", "--outputdir", dest="outputdir", default=os.getcwd(), help="Output directory.")

        self.options = self.processArguments(parser, arguments)

        if self.options is not None:
            if len(self.options.targets) == 0:
                parser.print_help()
                self.options = None

        return self.options

    def saveSpooler(self):
        files = [
            r".\spoolss.dll", 
            r".\spoolsv.exe", 
            r".\winspool.drv", 
            r".\en-US\spoolsv.exe.mui", 
            r".\en-US\winspool.drv.mui" 
        ]
        
        # Save old share
        old_share = self.smbSession.smb_share
        old_pwd = self.smbSession.smb_cwd

        temp_dir = tempfile.mkdtemp()
        self.logger.debug("Using temporary local directory '%s'" % temp_dir)
        self.smbSession.set_share('C$')
        if self.smbSession.path_isdir("/Windows/System32/"):
            self.smbSession.set_cwd("/Windows/System32/")
            for f in files:
                self.smbSession.get_file(path=f, keepRemotePath=True, localDownloadDir=temp_dir)
            self.smbSession.get_file_recursively(path="spool/", localDownloadDir=temp_dir)

        # Create a zipfile of the temp_dir
        pev = pe_get_version(temp_dir + os.path.sep + "spoolsv.exe")
        outputfile = '%s-spooler.zip' % pev["FileVersion"]
        zip_file_path = os.path.join(self.options.outputdir, outputfile)
        self.logger.info("Zipping files downloaded in '%s'" % temp_dir)
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    self.logger.print(os.path.join(root, file).replace(temp_dir+os.path.sep, "├──> ", 1))
                    zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), temp_dir))
        self.logger.info(f"Backup saved to {zip_file_path}")

        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

        # Restore old share
        self.smbSession.set_share(old_share)
        self.smbSession.set_cwd(old_pwd)

    #=[Run]====================================================================

    def run(self, arguments):
        self.options = self.parseArgs(arguments=arguments)

        if self.options is not None:
            # Entrypoint
            try:
                for t in self.options.targets:
                    if t == "spooler":
                        self.saveSpooler()
            except (BrokenPipeError, KeyboardInterrupt) as e:
                print("[!] Interrupted.")
                self.smbSession.close_smb_session()
                self.smbSession.init_smb_session()



