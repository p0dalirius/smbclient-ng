from __future__ import annotations
from impacket.dcerpc.v5 import transport, lsat, lsad, rpcrt
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.lsat import DCERPCSessionError
from impacket.nt_errors import STATUS_SOME_NOT_MAPPED, STATUS_NONE_MAPPED
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from impacket.smbconnection import SMBConnection

class SIDResolver:
    def __init__(self, smbConnection: SMBConnection):
        self.__smbConnection = smbConnection
        self.__dce = self.__get_lsarpc_binding()
        self.__dce.connect()
        self.__dce.bind(lsat.MSRPC_UUID_LSAT)
        self.cache = dict()
        
    def close(self):
        self.__dce.disconnect()

    def __get_lsarpc_binding(self) -> rpcrt.DCERPC_v5:
        rpctransport = transport.SMBTransport(445, filename = "lsarpc")
        rpctransport.set_smb_connection(self.__smbConnection)
        return rpctransport.get_dce_rpc()

    def resolve_sids(self, sids: set[str]) -> None:
        unresolved_sids = list(sids.difference(self.cache.keys()))
        if len(unresolved_sids) == 0:
            return
        resp = lsad.hLsarOpenPolicy2(self.__dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']
        try:
            resp = lsat.hLsarLookupSids(self.__dce, policyHandle, unresolved_sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCSessionError as err:
            #Catch error when some could not be resolved:
            if err.error_code == STATUS_SOME_NOT_MAPPED and err.packet != None:
                resp = err.packet
            elif err.error_code == STATUS_NONE_MAPPED:
                return
            else:
                raise err
        for i, item in enumerate(resp['TranslatedNames']['Names']):
            domain = resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name']
            if len(item['Name']) == 0:
                domain = domain + "\\" if len(domain) != 0 else ""
                cur_sid = f"{domain}Unknown (RID={unresolved_sids[i].split('-')[-1]})"
            elif len(domain) == 0:
                cur_sid = item['Name']
            else:
                cur_sid = "{}\\{}".format(domain, item['Name'])
            self.cache[unresolved_sids[i]] = cur_sid
    
    def get_sid(self, sid: str) -> str:
        if not sid in self.cache:
            self.resolve_sids({sid})
        return self.cache.get(sid) or sid