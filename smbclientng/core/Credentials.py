#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Credentials.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 mar 2025

from __future__ import annotations
from smbclientng.utils.utils import parse_lm_nt_hashes
import binascii
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Optional


class Credentials(object):
    """
    A class representing credentials for SMB connections.

    Attributes:
        domain (str): The domain of the user.
        username (str): The username of the user.
        password (str): The password of the user.
        nt_hex (str): The NT hash of the user.
        nt_raw (bytes): The raw NT hash of the user.
        lm_hex (str): The LM hash of the user.
        lm_raw (bytes): The raw LM hash of the user.
        use_kerberos (bool): Whether to use Kerberos for authentication.
        aesKey (str): The AES key for Kerberos authentication.
        kdcHost (str): The KDC host for Kerberos authentication.
    """

    # Identity
    domain: Optional[str]
    username: Optional[str]
    password: Optional[str]
    # Hashes
    nt_hex: str
    nt_raw: bytes
    lm_hex: str
    lm_raw: bytes
    # Kerberos
    use_kerberos: bool = False
    aesKey: Optional[str]
    kdcHost: Optional[str]

    def __init__(self, domain: str, username: str, password: str, hashes: Optional[str] = None, use_kerberos: bool = False, aesKey: Optional[str] = None, kdcHost: Optional[str] = None):
        super(Credentials, self).__init__()
        # Identity
        self.domain = domain
        self.username = username
        self.password = password

        # Hashes
        self.set_hashes(hashes=hashes)
        
        # Kerberos
        self.use_kerberos = use_kerberos
        self.kdcHost = kdcHost
        self.aesKey = aesKey

    def set_hashes(self, hashes: Optional[str]):
        """
        Sets the LM and NT hashes for the credentials.

        This method parses the provided hash string and sets the LM and NT hash values accordingly.
        If the hash string is valid and contains both LM and NT hashes, they are set directly.
        If only one hash is provided, the other is set to its default value.
        If the hash string is None or invalid, both hashes are set to None.

        Args:
            hashes (str): A string containing LM and NT hashes separated by a colon.
        """

        self.nt_hex = ""
        self.nt_raw = b""
        self.lm_hex = ""
        self.lm_raw = b""

        lmhash, nthash = None, None
        if hashes is not None:
            self.lm_hex, self.nt_hex = parse_lm_nt_hashes(hashes)
            if len(self.lm_hex) != 0:
                self.lm_raw = binascii.unhexlify(self.lm_hex)
            if len(self.nt_hex) != 0:
                self.nt_raw = binascii.unhexlify(self.nt_hex)

    def is_anonymous(self):
        """
        Determines if the credentials are anonymous.

        This method checks if the username is None or an empty string to determine if the credentials are anonymous.

        Returns:
            bool: True if the credentials are anonymous, False otherwise.
        """
        anonymous = False
        if self.username is None:
            anonymous = True
        elif len(self.username) == 0:
            anonymous = True
        else:
            anonymous = False
        return anonymous

    def canPassTheHash(self):
        """
        Determines if the current credentials can be used for a pass-the-hash attack.

        This method checks if both LM and NT hashes are available and not None. If both hashes are set,
        it indicates that the credentials may be used for a pass-the-hash attack.

        Returns:
            bool: True if both LM and NT hashes are available, False otherwise.
        """

        return bool(
            (self.nt_hex is not None)
            and (self.nt_raw is not None)
            and (self.lm_hex is not None)
            and (self.lm_raw is not None)
        )

    def __dict__(self):
        return {
            "domain": self.domain,
            "username": self.username,
            "password": self.password,
            "hashes": {
                "lm_hash": self.lm_hex,
                "nt_hash": self.nt_hex
            },
            "use_kerberos": self.use_kerberos,
            "aesKey": self.aesKey,
            "kdcHost": self.kdcHost
        }
    
    def __repr__(self):
        return f"<Credentials for '{self.domain}\\{self.username}'>"
