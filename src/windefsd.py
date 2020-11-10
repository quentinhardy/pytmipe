# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq
#Extracted and based on https://github.com/skelsec/winacl
#Big thanks to @skelsec for all these defintions

#Definitions for Security Descriptors ONLY

import io
import enum
from ctypes import *
import logging

class SE_OBJECT_TYPE(enum.Enum):
	SE_UNKNOWN_OBJECT_TYPE = 0 #Unknown object type.
	SE_FILE_OBJECT = 1 #Indicates a file or directory.
	SE_SERVICE = 2 #Indicates a Windows service
	SE_PRINTER = 3 #Indicates a printer.
	SE_REGISTRY_KEY = 4 #Indicates a registry key.
	SE_LMSHARE = 5 #Indicates a network share.
	SE_KERNEL_OBJECT = 6 #Indicates a local
	SE_WINDOW_OBJECT = 7 #Indicates a window station or desktop object on the local computer
	SE_DS_OBJECT = 8 #Indicates a directory service object or a property set or property of a directory service object.
	SE_DS_OBJECT_ALL = 9 #Indicates a directory service object and all of its property sets and properties.
	SE_PROVIDER_DEFINED_OBJECT = 10 #Indicates a provider-defined object.
	SE_WMIGUID_OBJECT = 11 #Indicates a WMI object.
	SE_REGISTRY_WOW64_32KEY = 12 #Indicates an object for a registry entry under WOW64.
	SE_REGISTRY_WOW64_64KEY = 13 #Indicates an object for a registry entry under WOW64.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
class SID:
    def __init__(self):
        self.Revision = None
        self.SubAuthorityCount = None
        self.IdentifierAuthority = None
        self.SubAuthority = []

        self.is_wellknown = None
        self.wellknow_name = None

        self.wildcard = None  # this is for well-known-sid lookups

    @staticmethod
    def wellknown_sid_lookup(x):
        if x in well_known_sids_sid_name_map:
            return well_known_sids_sid_name_map[x]
        return False

    @staticmethod
    def wellknown_name_lookup(x):
        if x in well_known_sids_name_sid_map:
            return well_known_sids_name_sid_map[x]
        return False

    @staticmethod
    def from_string(sid_str, wildcard=False):
        if sid_str[:4] != 'S-1-':
            raise Exception('This is not a SID')
        sid = SID()
        sid.wildcard = wildcard
        sid.Revision = 1
        sid_str = sid_str[4:]
        t = sid_str.split('-')[0]
        if t[:2] == '0x':
            sid.IdentifierAuthority = int(t[2:], 16)
        else:
            sid.IdentifierAuthority = int(t)

        for p in sid_str.split('-')[1:]:
            try:
                p = int(p)
            except Exception as e:
                if wildcard != True:
                    raise e
            sid.SubAuthority.append(p)
        return sid

    @staticmethod
    def from_bytes(data):
        return SID.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff):
        sid = SID()
        sid.Revision = int.from_bytes(buff.read(1), 'little', signed=False)
        sid.SubAuthorityCount = int.from_bytes(buff.read(1), 'little', signed=False)
        sid.IdentifierAuthority = int.from_bytes(buff.read(6), 'big', signed=False)
        for _ in range(sid.SubAuthorityCount):
            sid.SubAuthority.append(int.from_bytes(buff.read(4), 'little', signed=False))
        return sid

    def to_bytes(self):
        t = self.Revision.to_bytes(1, 'little', signed=False)
        t += len(self.SubAuthority).to_bytes(1, 'little', signed=False)
        t += self.IdentifierAuthority.to_bytes(6, 'big', signed=False)
        for i in self.SubAuthority:
            t += i.to_bytes(4, 'little', signed=False)
        return t

    def __str__(self):
        t = 'S-1-'
        if self.IdentifierAuthority < 2 ** 32:
            t += str(self.IdentifierAuthority)
        else:
            t += '0x' + self.IdentifierAuthority.to_bytes(6, 'big').hex().upper().rjust(12, '0')
        for i in self.SubAuthority:
            t += '-' + str(i)
        return t

    def __eq__(self, other):
        if isinstance(other, SID):
            return str(self) == str(other)
        return NotImplemented

    def to_ssdl(self):
        x = str(self)
        for val in ssdl_val_name_map:
            if isinstance(val, str) is True and val == x:
                return ssdl_val_name_map[val]
            elif isinstance(val, int) is True and self.SubAuthority[-1] == val:
                return ssdl_val_name_map[val]
        return x


# https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
# https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids

well_known_sids_name_sid_map = {
    'NULL': 'S-1-0-0',
    'EVERYONE': 'S-1-1-0',
    'LOCAL': 'S-1-2-0',
    'CONSOLE_LOGON': 'S-1-2-1',
    'CREATOR_OWNER': 'S-1-3-0',
    'CREATOR_GROUP': 'S-1-3-1',
    'OWNER_SERVER': 'S-1-3-2',
    'GROUP_SERVER': 'S-1-3-3',
    'OWNER_RIGHTS': 'S-1-3-4',
    'NT_AUTHORITY': 'S-1-5',
    'DIALUP': 'S-1-5-1',
    'NETWORK': 'S-1-5-2',
    'BATCH': 'S-1-5-3',
    'INTERACTIVE': 'S-1-5-4',
    'SERVICE': 'S-1-5-6',
    'ANONYMOUS': 'S-1-5-7',
    'PROXY': 'S-1-5-8',
    'ENTERPRISE_DOMAIN_CONTROLLERS': 'S-1-5-9',
    'PRINCIPAL_SELF': 'S-1-5-10',
    'AUTHENTICATED_USERS': 'S-1-5-11',
    'RESTRICTED_CODE': 'S-1-5-12',
    'TERMINAL_SERVER_USER': 'S-1-5-13',
    'REMOTE_INTERACTIVE_LOGON': 'S-1-5-14',
    'THIS_ORGANIZATION': 'S-1-5-15',
    'IUSR': 'S-1-5-17',
    'LOCAL_SYSTEM': 'S-1-5-18',
    'LOCAL_SERVICE': 'S-1-5-19',
    'NETWORK_SERVICE': 'S-1-5-20',
    'COMPOUNDED_AUTHENTICATION': 'S-1-5-21-0-0-0-496',
    'CLAIMS_VALID': 'S-1-5-21-0-0-0-497',
    'BUILTIN_ADMINISTRATORS': 'S-1-5-32-544',
    'BUILTIN_USERS': 'S-1-5-32-545',
    'BUILTIN_GUESTS': 'S-1-5-32-546',
    'POWER_USERS': 'S-1-5-32-547',
    'ACCOUNT_OPERATORS': 'S-1-5-32-548',
    'SERVER_OPERATORS': 'S-1-5-32-549',
    'PRINTER_OPERATORS': 'S-1-5-32-550',
    'BACKUP_OPERATORS': 'S-1-5-32-551',
    'REPLICATOR': 'S-1-5-32-552',
    'ALIAS_PREW2KCOMPACC': 'S-1-5-32-554',
    'REMOTE_DESKTOP': 'S-1-5-32-555',
    'NETWORK_CONFIGURATION_OPS': 'S-1-5-32-556',
    'INCOMING_FOREST_TRUST_BUILDERS': 'S-1-5-32-557',
    'PERFMON_USERS': 'S-1-5-32-558',
    'PERFLOG_USERS': 'S-1-5-32-559',
    'WINDOWS_AUTHORIZATION_ACCESS_GROUP': 'S-1-5-32-560',
    'TERMINAL_SERVER_LICENSE_SERVERS': 'S-1-5-32-561',
    'DISTRIBUTED_COM_USERS': 'S-1-5-32-562',
    'IIS_IUSRS': 'S-1-5-32-568',
    'CRYPTOGRAPHIC_OPERATORS': 'S-1-5-32-569',
    'EVENT_LOG_READERS': 'S-1-5-32-573',
    'CERTIFICATE_SERVICE_DCOM_ACCESS': 'S-1-5-32-574',
    'RDS_REMOTE_ACCESS_SERVERS': 'S-1-5-32-575',
    'RDS_ENDPOINT_SERVERS': 'S-1-5-32-576',
    'RDS_MANAGEMENT_SERVERS': 'S-1-5-32-577',
    'HYPER_V_ADMINS': 'S-1-5-32-578',
    'ACCESS_CONTROL_ASSISTANCE_OPS': 'S-1-5-32-579',
    'REMOTE_MANAGEMENT_USERS': 'S-1-5-32-580',
    'WRITE_RESTRICTED_CODE': 'S-1-5-33',
    'NTLM_AUTHENTICATION': 'S-1-5-64-10',
    'SCHANNEL_AUTHENTICATION': 'S-1-5-64-14',
    'DIGEST_AUTHENTICATION': 'S-1-5-64-21',
    'THIS_ORGANIZATION_CERTIFICATE': 'S-1-5-65-1',
    'NT_SERVICE': 'S-1-5-80',
    'USER_MODE_DRIVERS': 'S-1-5-84-0-0-0-0-0',
    'LOCAL_ACCOUNT': 'S-1-5-113',
    'LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP': 'S-1-5-114',
    'OTHER_ORGANIZATION': 'S-1-5-1000',
    'ALL_APP_PACKAGES': 'S-1-15-2-1',
    'ML_UNTRUSTED': 'S-1-16-0',
    'ML_LOW': 'S-1-16-4096',
    'ML_MEDIUM': 'S-1-16-8192',
    'ML_MEDIUM_PLUS': 'S-1-16-8448',
    'ML_HIGH': 'S-1-16-12288',
    'ML_SYSTEM': 'S-1-16-16384',
    'ML_PROTECTED_PROCESS': 'S-1-16-20480',
    'ML_SECURE_PROCESS': 'S-1-16-28672',
    'AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY': 'S-1-18-1',
    'SERVICE_ASSERTED_IDENTITY': 'S-1-18-2',
    'FRESH_PUBLIC_KEY_IDENTITY': 'S-1-18-3',
    'KEY_TRUST_IDENTITY': 'S-1-18-4',
    'KEY_PROPERTY_MFA': 'S-1-18-5',
    'KEY_PROPERTY_ATTESTATION': 'S-1-18-6',
}

well_known_sids_sid_name_map = {v: k for k, v in well_known_sids_name_sid_map.items()}

# below is the list of well-known SIDs which needs RE parsing for lookup
well_known_sids_re_name_sid_map = {
    'LOGON_ID': 'S-1-5-5-x-y',
    'ENTERPRISE_READONLY_DOMAIN_CONTROLLERS': 'S-1-5-21-<root domain>-498',
    'ADMINISTRATOR': 'S-1-5-21-<machine>-500',
    'GUEST': 'S-1-5-21-<machine>-501',
    'KRBTG': 'S-1-5-21-<domain>-502',
    'DOMAIN_ADMINS': 'S-1-5-21-<domain>-512',
    'DOMAIN_USERS': 'S-1-5-21-<domain>-513',
    'DOMAIN_GUESTS': 'S-1-5-21-<domain>-514',
    'DOMAIN_COMPUTERS': 'S-1-5-21-<domain>-515',
    'DOMAIN_DOMAIN_CONTROLLERS': 'S-1-5-21-<domain>-516',
    'CERT_PUBLISHERS': 'S-1-5-21-<domain>-517',
    'SCHEMA_ADMINISTRATORS': 'S-1-5-21-<root-domain>-518',
    'ENTERPRISE_ADMINS': 'S-1-5-21-<root-domain>-519',
    'GROUP_POLICY_CREATOR_OWNERS': 'S-1-5-21-<domain>-520',
    'READONLY_DOMAIN_CONTROLLERS': 'S-1-5-21-<domain>-521',
    'CLONEABLE_CONTROLLERS': 'S-1-5-21-<domain>-522',
    'PROTECTED_USERS': 'S-1-5-21-<domain>-525',
    'KEY_ADMINS': 'S-1-5-21-<domain>-526',
    'ENTERPRISE_KEY_ADMINS': 'S-1-5-21-<domain>-527',
    'RAS_SERVERS': 'S-1-5-21-<domain>-553',
    'ALLOWED_RODC_PASSWORD_REPLICATION_GROUP': 'S-1-5-21-<domain>-571',
    'DENIED_RODC_PASSWORD_REPLICATION_GROUP': 'S-1-5-21-<domain>-572',
}

well_known_sids_re_sid_name_map = {v: k for k, v in well_known_sids_re_name_sid_map.items()}


class DOMAIN_ALIAS_RID(enum.Enum):
    ADMINS = 0x00000220  # A local group used for administration of the domain.
    USERS = 0x00000221  # A local group that represents all users in the domain.
    GUESTS = 0x00000222  # A local group that represents guests of the domain.
    POWER_USERS = 0x00000223  # A local group used to represent a user or set of users who expect to treat a system as if it were their personal computer rather than as a workstation for multiple users.
    ACCOUNT_OPS = 0x00000224  # A local group that exists only on systems running server operating systems. This local group permits control over nonadministrator accounts.
    SYSTEM_OPS = 0x00000225  # A local group that exists only on systems running server operating systems. This local group performs system administrative functions, not including security functions. It establishes network shares, controls printers, unlocks workstations, and performs other operations.
    PRINT_OPS = 0x00000226  # A local group that exists only on systems running server operating systems. This local group controls printers and print queues.
    BACKUP_OPS = 0x00000227  # A local group used for controlling assignment of file backup-and-restore privileges.
    REPLICATOR = 0x00000228  # A local group responsible for copying security databases from the primary domain controller to the backup domain controllers. These accounts are used only by the system.
    RAS_SERVERS = 0x00000229  # A local group that represents RAS and IAS servers. This group permits access to various attributes of user objects.
    PREW2KCOMPACCESS = 0x0000022A  # A local group that exists only on systems running Windows 2000 Server. For more information, see Allowing Anonymous Access.
    REMOTE_DESKTOP_USERS = 0x0000022B  # A local group that represents all remote desktop users.
    NETWORK_CONFIGURATION_OPS = 0x0000022C  # A local group that represents the network configuration.
    INCOMING_FOREST_TRUST_BUILDERS = 0x0000022D  # A local group that represents any forest trust users.
    MONITORING_USERS = 0x0000022E  # A local group that represents all users being monitored.
    LOGGING_USERS = 0x0000022F  # A local group responsible for logging users.
    AUTHORIZATIONACCESS = 0x00000230  # A local group that represents all authorized access.
    TS_LICENSE_SERVERS = 0x00000231  # A local group that exists only on systems running server operating systems that allow for terminal services and remote access.
    DCOM_USERS = 0x00000232  # A local group that represents users who can use Distributed Component Object Model (DCOM).
    IUSERS = 0X00000238  # A local group that represents Internet users.
    CRYPTO_OPERATORS = 0x00000239  # A local group that represents access to cryptography operators.
    CACHEABLE_PRINCIPALS_GROUP = 0x0000023B  # A local group that represents principals that can be cached.
    NON_CACHEABLE_PRINCIPALS_GROUP = 0x0000023C  # A local group that represents principals that cannot be cached.
    EVENT_LOG_READERS_GROUP = 0x0000023D  # A local group that represents event log readers.
    CERTSVC_DCOM_ACCESS_GROUP = 0x0000023E  # The local group of users who can connect to certification authorities using Distributed Component Object Model (DCOM).
    RDS_REMOTE_ACCESS_SERVERS = 0x0000023F  # A local group that represents RDS remote access servers.
    RDS_ENDPOINT_SERVERS = 0x00000240  # A local group that represents endpoint servers.
    RDS_MANAGEMENT_SERVERS = 0x00000241  # A local group that represents management servers.
    HYPER_V_ADMINS = 0x00000242  # A local group that represents hyper-v admins
    ACCESS_CONTROL_ASSISTANCE_OPS = 0x00000243  # A local group that represents access control assistance OPS.
    REMOTE_MANAGEMENT_USERS = 0x00000244  # A local group that represents remote management users.
    DEFAULT_ACCOUNT = 0x00000245  # A local group that represents the default account.
    STORAGE_REPLICA_ADMINS = 0x00000246  # A local group that represents storage replica admins.
    DEVICE_OWNERS = 0x00000247  # A local group that represents can make settings expected for Device Owners.


class DOMAIN_GROUP_RID(enum.Enum):
    ADMINS = 0x00000200  # The domain administrators' group. This account exists only on systems running server operating systems.
    USERS = 0x00000201  # A group that contains all user accounts in a domain. All users are automatically added to this group.
    GUESTS = 0x00000202  # The guest-group account in a domain.
    COMPUTERS = 0x00000203  # The domain computers' group. All computers in the domain are members of this group.
    CONTROLLERS = 0x00000204  # The domain controllers' group. All DCs in the domain are members of this group.
    CERT_ADMINS = 0x00000205  # The certificate publishers' group. Computers running Certificate Services are members of this group.
    ENTERPRISE_READONLY_DOMAIN_CONTROLLERS = 0x000001F2  # The group of enterprise read-only domain controllers.
    SCHEMA_ADMINS = 0x00000206  # The schema administrators' group. Members of this group can modify the Active Directory schema.
    ENTERPRISE_ADMINS = 0x00000207  # The enterprise administrators' group. Members of this group have full access to all domains in the Active Directory forest. Enterprise administrators are responsible for forest-level operations such as adding or removing new domains.
    POLICY_ADMINS = 0x00000208  # The policy administrators' group.
    READONLY_CONTROLLERS = 0x00000209  # The group of read-only domain controllers.
    CLONEABLE_CONTROLLERS = 0x0000020A  # The group of cloneable domain controllers.
    CDC_RESERVED = 0x0000020C  # The reserved CDC group.
    PROTECTED_USERS = 0x0000020D  # The protected users group.
    KEY_ADMINS = 0x0000020E  # The key admins group.
    ENTERPRISE_KEY_ADMINS = 0x0000020F


class SECURITY_MANDATORY(enum.Enum):
    UNTRUSTED_RID = 0x00000000  # Untrusted.
    LOW_RID = 0x00001000  # Low integrity.
    MEDIUM_RID = 0x00002000  # Medium integrity.
    MEDIUM_PLUS_RID = 0x00002000 + 0x100  # Medium high integrity.
    HIGH_RID = 0x00003000  # High integrity.
    SYSTEM_RID = 0x00004000  # System integrity.
    PROTECTED_PROCESS_RID = 0x00005000


DOMAIN_USER_RID_ADMIN = 0x000001F4
DOMAIN_USER_RID_GUEST = 0x000001F5

SECURITY_LOCAL_SERVICE_RID = 0x00000013
SECURITY_SERVER_LOGON_RID = 9
SECURITY_NETWORK_SERVICE_RID = 0x00000014

# https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings
ssdl_name_val_map = {
    "AN": "S-1-5-7",  # Anonymous logon. The corresponding RID is SECURITY_ANONYMOUS_LOGON_RID.
    "AO": DOMAIN_ALIAS_RID.ACCOUNT_OPS.value,
    # Account operators. The corresponding RID is DOMAIN_ALIAS_RID_ACCOUNT_OPS.
    "AU": "S-1-5-11",  # Authenticated users. The corresponding RID is SECURITY_AUTHENTICATED_USER_RID.
    "BA": DOMAIN_ALIAS_RID.ADMINS.value,  # Built-in administrators. The corresponding RID is DOMAIN_ALIAS_RID_ADMINS.
    "BG": DOMAIN_ALIAS_RID.GUESTS.value,  # Built-in guests. The corresponding RID is DOMAIN_ALIAS_RID_GUESTS.
    "BO": DOMAIN_ALIAS_RID.BACKUP_OPS.value,  # Backup operators. The corresponding RID is DOMAIN_ALIAS_RID_BACKUP_OPS.
    "BU": DOMAIN_ALIAS_RID.USERS.value,  # Built-in users. The corresponding RID is DOMAIN_ALIAS_RID_USERS.
    "CA": DOMAIN_GROUP_RID.CERT_ADMINS.value,
    # Certificate publishers. The corresponding RID is DOMAIN_GROUP_RID_CERT_ADMINS.
    "CD": DOMAIN_ALIAS_RID.CERTSVC_DCOM_ACCESS_GROUP.value,
    # Users who can connect to certification authorities using Distributed Component Object Model (DCOM). The corresponding RID is DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP.
    "CG": "S-1-3",  # Creator group. The corresponding RID is SECURITY_CREATOR_GROUP_RID.
    "CO": "S-1-3",  # Creator owner. The corresponding RID is SECURITY_CREATOR_OWNER_RID.
    "DA": DOMAIN_GROUP_RID.ADMINS.value,  # Domain administrators. The corresponding RID is DOMAIN_GROUP_RID_ADMINS.
    "DC": DOMAIN_GROUP_RID.COMPUTERS.value,  # Domain computers. The corresponding RID is DOMAIN_GROUP_RID_COMPUTERS.
    "DD": DOMAIN_GROUP_RID.CONTROLLERS.value,
    # Domain controllers. The corresponding RID is DOMAIN_GROUP_RID_CONTROLLERS.
    "DG": DOMAIN_GROUP_RID.GUESTS.value,  # Domain guests. The corresponding RID is DOMAIN_GROUP_RID_GUESTS.
    "DU": DOMAIN_GROUP_RID.USERS.value,  # Domain users. The corresponding RID is DOMAIN_GROUP_RID_USERS.
    "EA": DOMAIN_GROUP_RID.ENTERPRISE_ADMINS.value,
    # Enterprise administrators. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_ADMINS.
    "ED": SECURITY_SERVER_LOGON_RID,
    # Enterprise domain controllers. The corresponding RID is SECURITY_SERVER_LOGON_RID.
    "HI": SECURITY_MANDATORY.HIGH_RID.value,
    # High integrity level. The corresponding RID is SECURITY_MANDATORY_HIGH_RID.
    "IU": "S-1-5-4",
    # Interactively logged-on user. This is a group identifier added to the token of a process when it was logged on interactively. The corresponding logon type is LOGON32_LOGON_INTERACTIVE. The corresponding RID is SECURITY_INTERACTIVE_RID.
    "LA": DOMAIN_USER_RID_ADMIN,  # Local administrator. The corresponding RID is DOMAIN_USER_RID_ADMIN.
    "LG": DOMAIN_USER_RID_GUEST,  # Local guest. The corresponding RID is DOMAIN_USER_RID_GUEST.
    "LS": SECURITY_LOCAL_SERVICE_RID,  # Local service account. The corresponding RID is SECURITY_LOCAL_SERVICE_RID.
    "LW": SECURITY_MANDATORY.LOW_RID.value,  # Low integrity level. The corresponding RID is SECURITY_MANDATORY_LOW_RID.
    "ME": SECURITY_MANDATORY.MEDIUM_RID.value,
    # Medium integrity level. The corresponding RID is SECURITY_MANDATORY_MEDIUM_RID.
    # TODO ERROR: NO VALUE FOUND FOR THIS! "MU" :  SDDL_PERFMON_USERS, #Performance Monitor users.
    "NO": DOMAIN_ALIAS_RID.NETWORK_CONFIGURATION_OPS.value,
    # Network configuration operators. The corresponding RID is DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS.
    "NS": SECURITY_NETWORK_SERVICE_RID,
    # Network service account. The corresponding RID is SECURITY_NETWORK_SERVICE_RID.
    "NU": "S-1-5-2",
    # Network logon user. This is a group identifier added to the token of a process when it was logged on across a network. The corresponding logon type is LOGON32_LOGON_NETWORK. The corresponding RID is SECURITY_NETWORK_RID.
    "PA": DOMAIN_GROUP_RID.POLICY_ADMINS.value,
    # Group Policy administrators. The corresponding RID is DOMAIN_GROUP_RID_POLICY_ADMINS.
    "PO": DOMAIN_ALIAS_RID.PRINT_OPS.value,  # Printer operators. The corresponding RID is DOMAIN_ALIAS_RID_PRINT_OPS.
    "PS": "S-1-5-10",  # Principal self. The corresponding RID is SECURITY_PRINCIPAL_SELF_RID.
    "PU": DOMAIN_ALIAS_RID.POWER_USERS.value,  # Power users. The corresponding RID is DOMAIN_ALIAS_RID_POWER_USERS.
    "RC": "S-1-5-12",
    # Restricted code. This is a restricted token created using the CreateRestrictedToken function. The corresponding RID is SECURITY_RESTRICTED_CODE_RID.
    "RD": DOMAIN_ALIAS_RID.REMOTE_DESKTOP_USERS.value,
    # Terminal server users. The corresponding RID is DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS.
    "RE": DOMAIN_ALIAS_RID.REPLICATOR.value,  # Replicator. The corresponding RID is DOMAIN_ALIAS_RID_REPLICATOR.
    "RO": DOMAIN_GROUP_RID.ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.value,
    # Enterprise Read-only domain controllers. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.
    "RS": DOMAIN_ALIAS_RID.RAS_SERVERS.value,
    # RAS servers group. The corresponding RID is DOMAIN_ALIAS_RID_RAS_SERVERS.
    "RU": DOMAIN_ALIAS_RID.PREW2KCOMPACCESS.value,
    # Alias to grant permissions to accounts that use applications compatible with operating systems previous to Windows 2000. The corresponding RID is DOMAIN_ALIAS_RID_PREW2KCOMPACCESS.
    "SA": DOMAIN_GROUP_RID.SCHEMA_ADMINS.value,
    # Schema administrators. The corresponding RID is DOMAIN_GROUP_RID_SCHEMA_ADMINS.
    "SI": SECURITY_MANDATORY.SYSTEM_RID.value,
    # System integrity level. The corresponding RID is SECURITY_MANDATORY_SYSTEM_RID.
    "SO": DOMAIN_ALIAS_RID.SYSTEM_OPS.value,  # Server operators. The corresponding RID is DOMAIN_ALIAS_RID_SYSTEM_OPS.
    "SU": "S-1-5-6",
    # Service logon user. This is a group identifier added to the token of a process when it was logged as a service. The corresponding logon type is LOGON32_LOGON_SERVICE. The corresponding RID is SECURITY_SERVICE_RID.
    "SY": "S-1-5-18",  # Local system. The corresponding RID is SECURITY_LOCAL_SYSTEM_RID.
    "WD": "S-1-1-0",
}

ssdl_val_name_map = {v: k for k, v in ssdl_name_val_map.items()}

# https://docs.microsoft.com/en-us/previous-versions/aa373931(v%3Dvs.80)
class GUID:
    def __init__(self):
        self.Data1 = None
        self.Data2 = None
        self.Data3 = None
        self.Data4 = None

    @staticmethod
    def from_buffer(buff):
        guid = GUID()
        guid.Data1 = buff.read(4)[::-1]
        guid.Data2 = buff.read(2)[::-1]
        guid.Data3 = buff.read(2)[::-1]
        guid.Data4 = buff.read(8)
        return guid

    @staticmethod
    def from_string(str):
        guid = GUID()
        guid.Data1 = bytes.fromhex(str.split('-')[0])
        guid.Data2 = bytes.fromhex(str.split('-')[1])
        guid.Data3 = bytes.fromhex(str.split('-')[2])
        guid.Data4 = bytes.fromhex(str.split('-')[3])
        guid.Data4 += bytes.fromhex(str.split('-')[4])
        return guid

    def __str__(self):
        return '-'.join(
            [self.Data1.hex(), self.Data2.hex(), self.Data3.hex(), self.Data4[:2].hex(), self.Data4[2:].hex()])

class ACCESS_MASK(enum.IntFlag):
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x4000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SYSTEM_SECURITY = 0x01000000


class STANDARD_ACCESS_MASK(enum.IntFlag):
    SYNCHRONIZE = 0x00100000
    WRITE_OWNER = 0x00080000
    WRITE_DACL = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000
    ALL = 0x00100000 | 0x00080000 | 0x00040000 | 0x00020000 | 0x00010000
    EXECUTE = 0x00020000
    READ = 0x00020000
    WRITE = 0x00020000
    REQUIRED = 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000


# https://docs.microsoft.com/en-us/previous-versions/tn-archive/ff405675(v%3dmsdn.10)
class ADS_ACCESS_MASK(enum.IntFlag):
    CREATE_CHILD = 0x00000001  # The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to create this type of child object.
    DELETE_CHILD = 0x00000002  # The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to delete this type of child object.

    ACTRL_DS_LIST = 0x00000004  # Enumerate a DS object.
    SELF = 0x00000008  # The ObjectType GUID identifies a validated write.
    READ_PROP = 0x00000010  # The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to read the property or property set.
    WRITE_PROP = 0x00000020  # The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to write the property or property set.

    DELETE_TREE = 0x00000040
    LIST_OBJECT = 0x00000080
    CONTROL_ACCESS = 0x00000100  # The ObjectType GUID identifies an extended access right.


class FILE_ACCESS_MASK(enum.IntFlag):
    # includes directory access as well
    FILE_READ_DATA = 1  # For a file object, the right to read the corresponding file data. For a directory object, the right to read the corresponding directory data.
    FILE_LIST_DIRECTORY = 1  # For a directory, the right to list the contents of the directory.
    FILE_ADD_FILE = 2  # For a directory, the right to create a file in the directory.
    FILE_WRITE_DATA = 2  # For a file object, the right to write data to the file. For a directory object, the right to create a file in the directory (FILE_ADD_FILE).
    FILE_ADD_SUBDIRECTORY = 4  # For a directory, the right to create a subdirectory.
    FILE_APPEND_DATA = 4  # For a file object, the right to append data to the file. (For local files, write operations will not overwrite existing data if this flag is specified without FILE_WRITE_DATA.) For a directory object, the right to create a subdirectory (FILE_ADD_SUBDIRECTORY).
    FILE_CREATE_PIPE_INSTANCE = 4  # For a named pipe, the right to create a pipe.
    FILE_READ_EA = 8  # The right to read extended file attributes.
    FILE_WRITE_EA = 16  # The right to write extended file attributes.
    FILE_EXECUTE = 32  # For a native code file, the right to execute the file. This access right given to scripts may cause the script to be executable, depending on the script interpreter.
    FILE_TRAVERSE = 32  # For a directory, the right to traverse the directory. By default, users are assigned the BYPASS_TRAVERSE_CHECKING privilege, which ignores the FILE_TRAVERSE access right. See the remarks in File Security and Access Rights for more information.
    FILE_DELETE_CHILD = 64  # For a directory, the right to delete a directory and all the files it contains, including read-only files.
    FILE_READ_ATTRIBUTES = 128  # The right to read file attributes.
    FILE_WRITE_ATTRIBUTES = 256  # The right to write file attributes.
    FILE_ALL_ACCESS = 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 256  # All possible access rights for a file.
    # STANDARD_RIGHTS_READ #Includes READ_CONTROL, which is the right to read the information in the file or directory object's security descriptor. This does not include the information in the SACL.
    # STANDARD_RIGHTS_WRITE #Same as STANDARD_RIGHTS_READ.
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x4000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    SYNCHRONIZE = 0x00100000
    WRITE_OWNER = 0x00080000
    WRITE_DACL = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000
    ALL = 0x00100000 | 0x00080000 | 0x00040000 | 0x00020000 | 0x00010000
    EXECUTE = 0x00020000
    READ = 0x00020000
    WRITE = 0x00020000
    REQUIRED = 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000


# FILE_RIGHTS = ACCESS_MASK + STANDARD_ACCESS_MASK + FILE_ACCESS_MASK

# https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?redirectedfrom=MSDN
class SC_MANAGER_ACCESS_MASK(enum.IntFlag):
    ALL_ACCESS = 0xF003F  # Includes STANDARD_RIGHTS_REQUIRED, in addition to all access rights in this table.
    CREATE_SERVICE = 0x0002  # Required to call the CreateService function to create a service object and add it to the database.
    CONNECT = 0x0001  # Required to connect to the service control manager.
    ENUMERATE_SERVICE = 0x0004  # Required to call the EnumServicesStatus or EnumServicesStatusEx function to list the services that are in the database. Required to call the NotifyServiceStatusChange function to receive notification when any service is created or deleted.
    LOCK = 0x0008  # Required to call the LockServiceDatabase function to acquire a lock on the database.
    MODIFY_BOOT_CONFIG = 0x0020  # Required to call the NotifyBootConfigStatus function.
    QUERY_LOCK_STATUS = 0x0010  # Required to call the QueryServiceLockStatus function to retrieve the lock status information for the database.

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x4000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000


# https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?redirectedfrom=MSDN
class SERVICE_ACCESS_MASK(enum.IntFlag):
    SERVICE_ALL_ACCESS = 0xF01FF  # Includes STANDARD_RIGHTS_REQUIRED in addition to all access rights in this table.
    SERVICE_CHANGE_CONFIG = 0x0002  # Required to call the ChangeServiceConfig or ChangeServiceConfig2 function to change the service configuration. Because this grants the caller the right to change the executable file that the system runs, it should be granted only to administrators.
    SERVICE_ENUMERATE_DEPENDENTS = 0x0008  # Required to call the EnumDependentServices function to enumerate all the services dependent on the service.
    SERVICE_INTERROGATE = 0x0080  # Required to call the ControlService function to ask the service to report its status immediately.
    SERVICE_PAUSE_CONTINUE = 0x0040  # Required to call the ControlService function to pause or continue the service.
    SERVICE_QUERY_CONFIG = 0x0001  # Required to call the QueryServiceConfig and QueryServiceConfig2 functions to query the service configuration.
    SERVICE_QUERY_STATUS = 0x0004  # Required to call the QueryServiceStatus or QueryServiceStatusEx function to ask the service control manager about the status of the service.
    # Required to call the NotifyServiceStatusChange function to receive notification when a service changes status.
    SERVICE_START = 0x0010  # Required to call the StartService function to start the service.
    SERVICE_STOP = 0x0020  # Required to call the ControlService function to stop the service.
    SERVICE_USER_DEFINED_CONTROL = 0x0100  # Required to call the ControlService function to specify a user-defined control code.

    # TODO : value for ?ACCESS_SYSTEM_SECURITY? 	Required to call the QueryServiceObjectSecurity or SetServiceObjectSecurity function to access the SACL. The proper way to obtain this access is to enable the SE_SECURITY_NAMEprivilege in the caller's current access token, open the handle for ACCESS_SYSTEM_SECURITY access, and then disable the privilege.
    DELETE = 0x10000  # Required to call the DeleteService function to delete the service.
    READ_CONTROL = 0x20000  # Required to call the QueryServiceObjectSecurity function to query the security descriptor of the service object.
    WRITE_DAC = 0x40000  # Required to call the SetServiceObjectSecurity function to modify the Dacl member of the service object's security descriptor.
    WRITE_OWNER = 0x80000  # Required to call the SetServiceObjectSecurity function to modify the Owner and Group members of the service object's security descriptor.


# https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights?redirectedfrom=MSDN
class REGISTRY_ACCESS_MASK(enum.IntFlag):
    KEY_ALL_ACCESS = 0xF003F  # Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
    KEY_CREATE_LINK = 0x0020  # Reserved for system use.
    KEY_CREATE_SUB_KEY = 0x0004  # Required to create a subkey of a registry key.
    KEY_ENUMERATE_SUB_KEYS = 0x0008  # Required to enumerate the subkeys of a registry key.
    KEY_EXECUTE = 0x20019  # Equivalent to KEY_READ.
    KEY_NOTIFY = 0x0010  # Required to request change notifications for a registry key or for subkeys of a registry key.
    KEY_QUERY_VALUE = 0x0001  # Required to query the values of a registry key.
    KEY_READ = 0x20019  # Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
    KEY_SET_VALUE = 0x0002  # Required to create, delete, or set a registry value.
    KEY_WOW64_32KEY = 0x0200  # Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. Windows 2000: This flag is not supported.
    KEY_WOW64_64KEY = 0x0100  # Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. Windows 2000: This flag is not supported.
    KEY_WRITE = 0x20006  # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.


# http://www.kouti.com/tables/baseattributes.htm

ExtendedRightsGUID = {
    'ee914b82-0a98-11d1-adbb-00c04fd8d5cd': 'Abandon Replication',
    '440820ad-65b4-11d1-a3da-0000f875ae0d': 'Add GUID',
    '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd': 'Allocate Rids',
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc': 'Allowed to Authenticate',
    'edacfd8f-ffb3-11d1-b41d-00a0c968f939': 'Apply Group Policy',
    '0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Certificate-Enrollment',
    '014bf69c-7b3b-11d1-85f6-08002be74fab': 'Change Domain Master',
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd': 'Change Infrastructure Master',
    'bae50096-4752-11d1-9052-00c04fc2d4cf': 'Change PDC',
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd': 'Change Rid Master',
    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd': 'Change-Schema-Master',
    'e2a36dc9-ae17-47c3-b58b-be34c55ba633': 'Create Inbound Forest Trust',
    'fec364e0-0a98-11d1-adbb-00c04fd8d5cd': 'Do Garbage Collection',
    'ab721a52-1e2f-11d0-9819-00aa0040529b': 'Domain-Administer-Server',
    '69ae6200-7f46-11d2-b9ad-00c04f79f805': 'Check Stale Phantoms',
    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e': 'Allow a DC to create a clone of itself',
    '2f16c4a5-b98e-432c-952a-cb388ba33f2e': 'Execute Forest Update Script',
    '9923a32a-3607-11d2-b9be-0000f87a36b2': 'Add/Remove Replica In Domain',
    '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc': 'Query Self Quota',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'Replicating Directory Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'Replicating Directory Changes All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'Replicating Directory Changes In Filtered Set',
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'Manage Replication Topology',
    'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96': 'Monitor Active Directory Replication',
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'Replication Synchronization',
    '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5': 'Enable Per User Reversibly Encrypted Password',
    'b7b1b3de-ab09-4242-9e30-9980e5d322f7': 'Generate Resultant Set of Policy (Logging)',
    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7': 'Generate Resultant Set of Policy (Planning)',
    '7c0e2a7c-a419-48e4-a995-10180aad54dd': 'Manage Optional Features for Active Directory',
    'ba33815a-4f93-4c76-87f3-57574bff8109': 'Migrate SID History',
    'b4e60130-df3f-11d1-9c86-006008764d0e': 'Open Connector Queue',
    '06bd3201-df3e-11d1-9c86-006008764d0e': 'Allows peeking at messages in the queue.',
    '4b6e08c3-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-computer-Journal',
    '4b6e08c1-df3c-11d1-9c86-006008764d0e': 'Peek Dead Letter',
    '06bd3200-df3e-11d1-9c86-006008764d0e': 'Receive Message',
    '4b6e08c2-df3c-11d1-9c86-006008764d0e': 'Receive Computer Journal',
    '4b6e08c0-df3c-11d1-9c86-006008764d0e': 'Receive Dead Letter',
    '06bd3203-df3e-11d1-9c86-006008764d0e': 'Receive Journal',
    '06bd3202-df3e-11d1-9c86-006008764d0e': 'Send Message',
    'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open Address List',
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2': 'Read Only Replication Secret Synchronization',
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f': 'Reanimate Tombstones',
    '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd': 'Recalculate Hierarchy',
    '62dd28a8-7f46-11d2-b9ad-00c04f79f805': 'Recalculate Security Inheritance',
    'ab721a56-1e2f-11d0-9819-00aa0040529b': 'Receive As',
    '9432c620-033c-4db7-8b58-14ef6d0bf477': 'Refresh Group Cache for Logons',
    '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8': 'Reload SSL/TLS Certificate',
    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f': 'Run Protect Admin Groups Task',
    '91d67418-0135-4acc-8d79-c08e857cfbec': 'Enumerate Entire SAM Domain',
    'ab721a54-1e2f-11d0-9819-00aa0040529b': 'Send As',
    'ab721a55-1e2f-11d0-9819-00aa0040529b': 'Send To',
    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501': 'Unexpire Password',
    '280f369c-67c7-438e-ae98-1d46f3c6f541': 'Update Password Not Required Bit',
    'be2bb760-7f46-11d2-b9ad-00c04f79f805': 'Update Schema Cache',
    'ab721a53-1e2f-11d0-9819-00aa0040529b': 'Change Password',
    '00299570-246d-11d0-a768-00aa006e0529': 'Reset Password',
}

PropertySets = {
    '72e39547-7b18-11d1-adef-00c04fd8d5cd': 'DNS Host Name Attributes',
    'b8119fd0-04f6-4762-ab7a-4986c76b3f9a': 'Other Domain Parameters (for use by SAM)',
    'c7407360-20bf-11d0-a768-00aa006e0529': 'Domain Password & Lockout Policies',
    'e45795b2-9455-11d1-aebd-0000f80367c1': 'Phone and Mail Options',
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf': 'General Information',
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf': 'Group Membership',
    'ffa6f046-ca4b-4feb-b40d-04dfee722543': 'MS-TS-GatewayAccess',
    '77b5b886-944a-11d1-aebd-0000f80367c1': 'Personal Information',
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8': 'Private Information',
    'e48d0154-bcf8-11d1-8702-00c04fb96050': 'Public Information',
    '037088f8-0ae1-11d2-b422-00a0c968f939': 'Remote Access Information',
    '5805bc62-bdc9-4428-a5e2-856a0f4c185e': 'Terminal Server License Server',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'Account Restrictions',
    '5f202010-79a5-11d0-9020-00c04fc2d4cf': 'Logon Information',
    'e45795b3-9455-11d1-aebd-0000f80367c1': 'Web Information',
}

ValidatedWrites = {
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Add/Remove self as member',
    '72e39547-7b18-11d1-adef-00c04fd8d5cd': 'Validated write to DNS host name',
    '80863791-dbe9-4eb8-837e-7f0ab55d9ac7': 'Validated write to MS DS Additional DNS Host Name',
    'd31a8757-2447-4545-8081-3bb610cacbf2': 'Validated write to MS DS behavior version',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Validated write to service principal name',
}


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEType(enum.Enum):
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01
    SYSTEM_AUDIT_ACE_TYPE = 0x02
    SYSTEM_ALARM_ACE_TYPE = 0x03
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13


class AceFlags(enum.IntFlag):
    CONTAINER_INHERIT_ACE = 0x02
    FAILED_ACCESS_ACE_FLAG = 0x80
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10
    NO_PROPAGATE_INHERIT_ACE = 0x04
    OBJECT_INHERIT_ACE = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40


# https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)

SSDL_ACE_TYPE_MAPS = {
    "ALLOW": ACEType.ACCESS_ALLOWED_ACE_TYPE,
    "DENIED": ACEType.ACCESS_DENIED_ACE_TYPE,
    "O_ALLOW": ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    "O_DENIED": ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE,
    "AUDIT": ACEType.SYSTEM_AUDIT_ACE_TYPE,
    "ALARM": ACEType.SYSTEM_ALARM_ACE_TYPE,
    "O_AUDIT": ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    "O_ALARM": ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE,
    "MANDATORY": ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    "C_ALLOW": ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE,  # Windows Vista and Windows Server 2003: Not available.
    "C_DENIED": ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE,  # Windows Vista and Windows Server 2003: Not available.
    "S_RESOURCE": ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
    # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
    "S_SCOPED": ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
    # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
    "S_AUDIT": ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
    "A_ALLOW": ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
}
SSDL_ACE_TYPE_MAPS_INV = {v: k for k, v in SSDL_ACE_TYPE_MAPS.items()}

SSDL_ACE_FLAGS_MAPS = {
    "CI": AceFlags.CONTAINER_INHERIT_ACE,
    "OI": AceFlags.OBJECT_INHERIT_ACE,
    "NP": AceFlags.NO_PROPAGATE_INHERIT_ACE,
    "IO": AceFlags.INHERIT_ONLY_ACE,
    "ID": AceFlags.INHERITED_ACE,
    "SA": AceFlags.SUCCESSFUL_ACCESS_ACE_FLAG,
    "FA": AceFlags.FAILED_ACCESS_ACE_FLAG,
}
SSDL_ACE_FLAGS_MAPS_INV = {v: k for k, v in SSDL_ACE_FLAGS_MAPS.items()}

ssdl_generic_rights_maps = {
    "GA": ACCESS_MASK.GENERIC_ALL,
    "GR": ACCESS_MASK.GENERIC_READ,
    "GW": ACCESS_MASK.GENERIC_WRITE,
    "GX": ACCESS_MASK.GENERIC_EXECUTE,
}

ssdl_standard_rights_maps = {
    "RC": STANDARD_ACCESS_MASK.READ_CONTROL,
    "SD": STANDARD_ACCESS_MASK.DELETE,
    "WD": STANDARD_ACCESS_MASK.WRITE_DACL,
    "WO": STANDARD_ACCESS_MASK.WRITE_OWNER,
}

ssdl_ds_rights_maps = {
    "RP": ADS_ACCESS_MASK.READ_PROP,
    "WP": ADS_ACCESS_MASK.WRITE_PROP,
    "CC": ADS_ACCESS_MASK.CREATE_CHILD,
    "DC": ADS_ACCESS_MASK.DELETE_CHILD,
    "LC": ADS_ACCESS_MASK.ACTRL_DS_LIST,
    "SW": ADS_ACCESS_MASK.SELF,
    "LO": ADS_ACCESS_MASK.LIST_OBJECT,
    "DT": ADS_ACCESS_MASK.DELETE_TREE,
    "CR": ADS_ACCESS_MASK.CONTROL_ACCESS,
}

ssdl_file_rights_maps = {
    "FA": FILE_ACCESS_MASK.FILE_ALL_ACCESS,
    "FR": FILE_ACCESS_MASK.SYNCHRONIZE | FILE_ACCESS_MASK.READ_CONTROL | FILE_ACCESS_MASK.FILE_READ_ATTRIBUTES | FILE_ACCESS_MASK.FILE_READ_EA | FILE_ACCESS_MASK.FILE_READ_DATA,
    # TODO "FW" : STANDARD_ACCESS_MASK.WRITE,
    # TODO "FX" : STANDARD_ACCESS_MASK.EXECUTE,
}
ssdl_file_rights_maps_inv = {v: k for k, v in ssdl_file_rights_maps.items()}


# TODO implement registry and mandatory label
# ssdl_registry_rights_maps = {
#	"KA" 	SDDL_KEY_ALL 	KEY_ALL_ACCESS
#	"KR" 	SDDL_KEY_READ 	KEY_READ
#	"KW" 	SDDL_KEY_WRITE 	KEY_WRITE
#	"KX" 	SDDL_KEY_EXECUTE 	KEY_EXECUTE
# }
#
# ssdl_mandatory_label_rights_maps = {
# "NR" 	SDDL_NO_READ_UP 	SYSTEM_MANDATORY_LABEL_NO_READ_UP
# "NW" 	SDDL_NO_WRITE_UP 	SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
# "NX" 	SDDL_NO_EXECUTE_UP 	SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
# }

def mask_to_str(mask, sd_object_type=None):
    if sd_object_type == SE_OBJECT_TYPE.SE_FILE_OBJECT:
        return str(FILE_ACCESS_MASK(mask))
    elif sd_object_type == SE_OBJECT_TYPE.SE_SERVICE:
        return str(SERVICE_ACCESS_MASK(mask))
    elif sd_object_type == SE_OBJECT_TYPE.SE_REGISTRY_KEY:
        return str(REGISTRY_ACCESS_MASK(mask))
    else:
        return hex(mask)


def aceflags_to_ssdl(flags):
    t = ''
    for k in SSDL_ACE_FLAGS_MAPS_INV:
        if k in flags:
            t += SSDL_ACE_FLAGS_MAPS_INV[k]
    return t


def accessmask_to_sddl(mask, sd_object_type):
    t = ''
    if sd_object_type == SE_OBJECT_TYPE.SE_FILE_OBJECT:
        if FILE_ACCESS_MASK.FILE_ALL_ACCESS in FILE_ACCESS_MASK(mask):
            return ssdl_file_rights_maps_inv[FILE_ACCESS_MASK.FILE_ALL_ACCESS]
        elif STANDARD_ACCESS_MASK.READ in STANDARD_ACCESS_MASK(mask):
            return ssdl_file_rights_maps_inv[STANDARD_ACCESS_MASK.READ]
        elif STANDARD_ACCESS_MASK.WRITE in STANDARD_ACCESS_MASK(mask):
            return ssdl_file_rights_maps_inv[STANDARD_ACCESS_MASK.WRITE]
        else:
            return hex(mask)
    return hex(mask)


class ACE:
    def __init__(self):
        pass

    @staticmethod
    def from_bytes(data, sd_object_type=None):
        return ACE.from_buffer(io.BytesIO(data), sd_object_type)

    @staticmethod
    def from_buffer(buff, sd_object_type=None):
        hdr = ACEHeader.pre_parse(buff)
        obj = acetype2ace.get(hdr.AceType)
        if not obj:
            raise Exception('ACE type %s not implemented!' % hdr.AceType)
            #logging.error('ACE type %s not implemented!' % hdr.AceType)
            #return None
        return obj.from_buffer(io.BytesIO(buff.read(hdr.AceSize)), sd_object_type)

    def to_buffer(self, buff):
        pass

    def to_bytes(self):
        buff = io.BytesIO()
        self.to_buffer(buff)
        buff.seek(0)
        return buff.read()

    def to_ssdl(self, sd_object_type=None):
        pass

    @staticmethod
    def add_padding(x):
        if (4 + len(x)) % 4 != 0:
            x += b'\x00' * ((4 + len(x)) % 4)
        return x

    @staticmethod
    def from_ssdl(x):
        pass


class ACCESS_ALLOWED_ACE(ACE):
    def __init__(self):
        self.AceType = ACEType.ACCESS_ALLOWED_ACE_TYPE
        self.AceFlags = None
        self.AceSize = 0
        self.Mask = None
        self.Sid = None
        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type=None):
        ace = ACCESS_ALLOWED_ACE()
        ace.sd_object_type = SE_OBJECT_TYPE(sd_object_type) if sd_object_type else None
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def to_ssdl(self, sd_object_type=None):
        # ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
        return '(%s;%s;%s;%s;%s;%s)' % (
            SSDL_ACE_TYPE_MAPS_INV[self.AceType],
            aceflags_to_ssdl(self.AceFlags),
            accessmask_to_sddl(self.Mask, self.sd_object_type),
            '',
            '',
            self.Sid.to_ssdl()
        )

    def to_dict(self, sd_object_type=None):
        return {'ace_type':SSDL_ACE_TYPE_MAPS_INV[self.AceType],
                'ace_flags':aceflags_to_ssdl(self.AceFlags),
                'rights':accessmask_to_sddl(self.Mask, self.sd_object_type),
                'object_guid':'',
                'inherit_object_guid':'',
                'account_sid':str(self.Sid)}

    def __str__(self):
        t = 'ACCESS_ALLOWED_ACE\r\n'
        t += 'Flags: %s\r\n' % str(self.AceFlags)
        t += 'Sid: %s\r\n' % self.Sid
        t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
        return t


class ACCESS_DENIED_ACE(ACE):
    def __init__(self):
        self.AceType = ACEType.ACCESS_DENIED_ACE_TYPE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        ace = ACCESS_DENIED_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def to_ssdl(self, sd_object_type=None):
        # ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
        return '(%s;%s;%s;%s;%s;%s)' % (
            SSDL_ACE_TYPE_MAPS_INV[self.Header.AceType],
            aceflags_to_ssdl(self.Header.AceFlags),
            accessmask_to_sddl(self.Mask, self.sd_object_type),
            '',
            '',
            self.Sid.to_ssdl()
        )

    def to_dict(self, sd_object_type=None):
        return {'ace_type':SSDL_ACE_TYPE_MAPS_INV[self.AceType],
                'ace_flags':aceflags_to_ssdl(self.AceFlags),
                'rights':accessmask_to_sddl(self.Mask, self.sd_object_type),
                'object_guid':'',
                'inherit_object_guid':'',
                'account_sid':str(self.Sid)}


class SYSTEM_AUDIT_ACE(ACE):
    def __init__(self):
        self.AceType = ACEType.SYSTEM_AUDIT_ACE_TYPE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        ace = SYSTEM_AUDIT_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def to_ssdl(self, sd_object_type=None):
        # ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
        return '(%s;%s;%s;%s;%s;%s)' % (
            SSDL_ACE_TYPE_MAPS_INV[self.AceType],
            aceflags_to_ssdl(self.AceFlags),
            accessmask_to_sddl(self.Mask, self.sd_object_type),
            '',
            '',
            self.Sid.to_ssdl()
        )

    def to_dict(self, sd_object_type=None):
        return {'ace_type':SSDL_ACE_TYPE_MAPS_INV[self.AceType],
                'ace_flags':aceflags_to_ssdl(self.AceFlags),
                'rights':accessmask_to_sddl(self.Mask, self.sd_object_type),
                'object_guid':'',
                'inherit_object_guid':'',
                'account_sid':str(self.Sid)}


class SYSTEM_ALARM_ACE(ACE):
    def __init__(self):
        self.AceType = ACEType.SYSTEM_ALARM_ACE_TYPE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        ace = SYSTEM_ALARM_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def to_ssdl(self, sd_object_type=None):
        # ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
        return '(%s;%s;%s;%s;%s;%s)' % (
            SSDL_ACE_TYPE_MAPS_INV[self.Header.AceType],
            aceflags_to_ssdl(self.Header.AceFlags),
            accessmask_to_sddl(self.Mask, self.sd_object_type),
            '',
            '',
            self.Sid.to_ssdl()
        )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ACCESS_ALLOWED_OBJECT_Flags(enum.IntFlag):
    NONE = 0x00000000  # Neither ObjectType nor InheritedObjectType are valid.
    ACE_OBJECT_TYPE_PRESENT = 0x00000001  # ObjectType is valid.
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002  # InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.


class ACCESS_ALLOWED_OBJECT_ACE:
    def __init__(self):
        self.AceType = ACEType.ACCESS_ALLOWED_OBJECT_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Flags = None
        self.ObjectType = None
        self.InheritedObjectType = None
        self.Sid = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        ace = ACCESS_ALLOWED_OBJECT_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed=False))
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            ace.ObjectType = GUID.from_buffer(buff)
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            ace.InheritedObjectType = GUID.from_buffer(buff)
        ace.Sid = SID.from_buffer(buff)
        return ace

    def to_buffer(self, buff):
        if self.ObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT
        if self.InheritedObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT

        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Flags.to_bytes(4, 'little', signed=False)
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            t += self.ObjectType.to_bytes()
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            t += self.InheritedObjectType.to_bytes()

        t += self.Sid.to_bytes()
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def to_ssdl(self, sd_object_type=None):
        # ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
        return '(%s;%s;%s;%s;%s;%s)' % (
            SSDL_ACE_TYPE_MAPS_INV[self.Header.AceType],
            aceflags_to_ssdl(self.Header.AceFlags),
            accessmask_to_sddl(self.Mask, self.sd_object_type),
            self.ObjectType.to_bytes() if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT else '',
            self.InheritedObjectType.to_bytes() if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT else '',
            self.Sid.to_ssdl()
        )

    def __str__(self):
        t = 'ACCESS_ALLOWED_OBJECT_ACE'
        t += 'ObjectType: %s\r\n' % self.ObjectType
        t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
        t += 'ObjectFlags: %s\r\n' % self.Flags
        t += 'AccessControlType: Allow\r\n'

        return t


class ACCESS_DENIED_OBJECT_ACE:
    def __init__(self):
        self.AceType = ACEType.ACCESS_DENIED_OBJECT_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Flags = None
        self.ObjectType = None
        self.InheritedObjectType = None
        self.Sid = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        ace = ACCESS_DENIED_OBJECT_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed=False))
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            ace.ObjectType = GUID.from_buffer(buff)
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            ace.InheritedObjectType = GUID.from_buffer(buff)
        ace.Sid = SID.from_buffer(buff)
        return ace

    def to_buffer(self, buff):
        if self.ObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT
        if self.InheritedObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT

        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Flags.to_bytes(4, 'little', signed=False)
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            t += self.ObjectType.to_bytes()
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            t += self.InheritedObjectType.to_bytes()

        t += self.Sid.to_bytes()
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def to_ssdl(self, sd_object_type=None):
        # ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
        return '(%s;%s;%s;%s;%s;%s)' % (
            SSDL_ACE_TYPE_MAPS_INV[self.Header.AceType],
            aceflags_to_ssdl(self.Header.AceFlags),
            accessmask_to_sddl(self.Mask, self.sd_object_type),
            self.ObjectType.to_bytes() if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT else '',
            self.InheritedObjectType.to_bytes() if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT else '',
            self.Sid.to_ssdl()
        )

    def __str__(self):
        t = 'ACCESS_DENIED_OBJECT_ACE'
        t += 'ObjectType: %s\r\n' % self.ObjectType
        t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
        t += 'ObjectFlags: %s\r\n' % self.Flags
        t += 'AccessControlType: Allow\r\n'

        return t


class SYSTEM_AUDIT_OBJECT_ACE:
    def __init__(self):
        self.AceType = ACEType.SYSTEM_AUDIT_OBJECT_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Flags = None
        self.ObjectType = None
        self.InheritedObjectType = None
        self.Sid = None
        self.ApplicationData = None  # must be bytes!

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        start = buff.tell()
        ace = SYSTEM_AUDIT_OBJECT_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed=False))
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            ace.ObjectType = GUID.from_buffer(buff)
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            ace.InheritedObjectType = GUID.from_buffer(buff)
        ace.Sid = SID.from_buffer(buff)
        ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
        return ace

    def to_buffer(self, buff):
        if self.ObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT
        if self.InheritedObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT

        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Flags.to_bytes(4, 'little', signed=False)
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            t += self.ObjectType.to_bytes()
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            t += self.InheritedObjectType.to_bytes()

        t += self.Sid.to_bytes()
        t += self.ApplicationData
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    # def to_ssdl(self, sd_object_type = None):
    #	#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
    #	return '(%s;%s;%s;%s;%s;%s)' % (
    #		SSDL_ACE_TYPE_MAPS_INV[self.Header.AceType],
    #		aceflags_to_ssdl(self.Header.AceFlags),
    #		accessmask_to_sddl(self.Mask, self.sd_object_type),
    #		self.ObjectType.to_bytes() if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT else '' ,
    #		self.InheritedObjectType.to_bytes() if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT else '',
    #		self.Sid.to_ssdl()
    #	)

    def __str__(self):
        t = 'SYSTEM_AUDIT_OBJECT_ACE'
        t += 'ObjectType: %s\r\n' % self.ObjectType
        t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
        t += 'ObjectFlags: %s\r\n' % self.Flags
        t += 'AccessControlType: Allow\r\n'

        return t


class ACCESS_ALLOWED_CALLBACK_ACE:
    def __init__(self):
        self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None
        self.ApplicationData = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        start = buff.tell()
        ace = ACCESS_ALLOWED_CALLBACK_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t += self.ApplicationData
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def __str__(self):
        t = 'ACCESS_ALLOWED_CALLBACK_ACE'
        t += 'Header: %s\r\n' % self.Header
        t += 'Mask: %s\r\n' % self.Mask
        t += 'Sid: %s\r\n' % self.Sid
        t += 'ApplicationData: %s \r\n' % self.ApplicationData

        return t


class ACCESS_DENIED_CALLBACK_ACE:
    def __init__(self):
        self.AceType = ACEType.ACCESS_DENIED_CALLBACK_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None
        self.ApplicationData = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        start = buff.tell()
        ace = ACCESS_DENIED_CALLBACK_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t += self.ApplicationData
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def __str__(self):
        t = 'ACCESS_DENIED_CALLBACK_ACE'
        t += 'Header: %s\r\n' % self.Header
        t += 'Mask: %s\r\n' % self.Mask
        t += 'Sid: %s\r\n' % self.Sid
        t += 'ApplicationData: %s \r\n' % self.ApplicationData

        return t


class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE:
    def __init__(self):
        self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Flags = None
        self.ObjectType = None
        self.InheritedObjectType = None
        self.Sid = None
        self.ApplicationData = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        start = buff.tell()
        ace = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed=False))
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            ace.ObjectType = GUID.from_buffer(buff)
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            ace.InheritedObjectType = GUID.from_buffer(buff)
        ace.Sid = SID.from_buffer(buff)
        ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
        return ace

    def to_buffer(self, buff):
        if self.ObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT
        if self.InheritedObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT

        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Flags.to_bytes(4, 'little', signed=False)
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            t += self.ObjectType.to_bytes()
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            t += self.InheritedObjectType.to_bytes()

        t += self.Sid.to_bytes()
        t += self.ApplicationData
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def __str__(self):
        t = 'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE'
        t += 'ObjectType: %s\r\n' % self.ObjectType
        t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
        t += 'ObjectFlags: %s\r\n' % self.Flags
        t += 'ApplicationData: %s \r\n' % self.ApplicationData

        return t


class ACCESS_DENIED_CALLBACK_OBJECT_ACE:
    def __init__(self):
        self.AceType = ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Flags = None
        self.ObjectType = None
        self.InheritedObjectType = None
        self.Sid = None
        self.ApplicationData = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff):
        start = buff.tell()
        ace = ACCESS_DENIED_CALLBACK_OBJECT_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed=False))
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            ace.ObjectType = GUID.from_buffer(buff)
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            ace.InheritedObjectType = GUID.from_buffer(buff)
        ace.Sid = SID.from_buffer(buff)
        ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
        return ace

    def to_buffer(self, buff):
        if self.ObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT
        if self.InheritedObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT

        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Flags.to_bytes(4, 'little', signed=False)
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            t += self.ObjectType.to_bytes()
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            t += self.InheritedObjectType.to_bytes()

        t += self.Sid.to_bytes()
        t += self.ApplicationData
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def __str__(self):
        t = 'ACCESS_DENIED_CALLBACK_OBJECT_ACE'
        t += 'ObjectType: %s\r\n' % self.ObjectType
        t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
        t += 'ObjectFlags: %s\r\n' % self.Flags
        t += 'ApplicationData: %s \r\n' % self.ApplicationData

        return t


class SYSTEM_AUDIT_CALLBACK_ACE:
    def __init__(self):
        self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None
        self.ApplicationData = None

        self.sd_object_type = sd_object_type

    @staticmethod
    def from_buffer(buff, sd_object_type):
        start = buff.tell()
        ace = SYSTEM_AUDIT_CALLBACK_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t += self.ApplicationData
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def __str__(self):
        t = 'SYSTEM_AUDIT_CALLBACK_ACE'
        t += 'Header: %s\r\n' % self.Header
        t += 'Mask: %s\r\n' % self.Mask
        t += 'Sid: %s\r\n' % self.Sid
        t += 'ApplicationData: %s \r\n' % self.ApplicationData

        return t


class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE:
    def __init__(self):
        self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Flags = None
        self.ObjectType = None
        self.InheritedObjectType = None
        self.Sid = None
        self.ApplicationData = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        start = buff.tell()
        ace = SYSTEM_AUDIT_CALLBACK_OBJECT_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed=False))
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            ace.ObjectType = GUID.from_buffer(buff)
        if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            ace.InheritedObjectType = GUID.from_buffer(buff)
        ace.Sid = SID.from_buffer(buff)
        ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
        return ace

    def to_buffer(self, buff):
        if self.ObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT
        if self.InheritedObjectType is not None:
            self.Flags |= ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT

        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Flags.to_bytes(4, 'little', signed=False)
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
            t += self.ObjectType.to_bytes()
        if self.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            t += self.InheritedObjectType.to_bytes()

        t += self.Sid.to_bytes()
        t += self.ApplicationData
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def __str__(self):
        t = 'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE'
        t += 'ObjectType: %s\r\n' % self.ObjectType
        t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
        t += 'ObjectFlags: %s\r\n' % self.Flags
        t += 'ApplicationData: %s \r\n' % self.ApplicationData

        return t


class SYSTEM_MANDATORY_LABEL_ACE:
    def __init__(self):
        self.AceType = ACEType.SYSTEM_MANDATORY_LABEL_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None

        self.sd_object_type = sd_object_type

    @staticmethod
    def from_buffer(buff, sd_object_type):
        ace = SYSTEM_MANDATORY_LABEL_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)


class SYSTEM_RESOURCE_ATTRIBUTE_ACE:
    def __init__(self):
        self.AceType = ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None
        self.AttributeData = None  # must be bytes for now. structure is TODO (see top of file)

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        start = buff.tell()
        ace = SYSTEM_RESOURCE_ATTRIBUTE_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        ace.AttributeData = buff.read(ace.AceSize - (buff.tell() - start))
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t += self.AttributeData
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)

    def __str__(self):
        t = 'SYSTEM_RESOURCE_ATTRIBUTE_ACE'
        t += 'Header: %s\r\n' % self.Header
        t += 'Mask: %s\r\n' % self.Mask
        t += 'Sid: %s\r\n' % self.Sid
        t += 'AttributeData: %s \r\n' % self.AttributeData

        return t


class SYSTEM_SCOPED_POLICY_ID_ACE:
    def __init__(self):
        self.AceType = ACEType.SYSTEM_SCOPED_POLICY_ID_ACE
        self.AceFlags = None
        self.AceSize = None
        self.Mask = None
        self.Sid = None

        self.sd_object_type = None

    @staticmethod
    def from_buffer(buff, sd_object_type):
        ace = SYSTEM_SCOPED_POLICY_ID_ACE()
        ace.sd_object_type = sd_object_type
        ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        ace.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        ace.Mask = int.from_bytes(buff.read(4), 'little', signed=False)
        ace.Sid = SID.from_buffer(buff)
        return ace

    def to_buffer(self, buff):
        t = self.Mask.to_bytes(4, 'little', signed=False)
        t += self.Sid.to_bytes()
        t = ACE.add_padding(t)
        self.AceSize = 4 + len(t)
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))
        buff.write(t)


acetype2ace = {
    ACEType.ACCESS_ALLOWED_ACE_TYPE: ACCESS_ALLOWED_ACE,
    ACEType.ACCESS_DENIED_ACE_TYPE: ACCESS_DENIED_ACE,
    ACEType.SYSTEM_AUDIT_ACE_TYPE: SYSTEM_AUDIT_ACE,
    ACEType.SYSTEM_ALARM_ACE_TYPE: SYSTEM_ALARM_ACE,
    ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE: ACCESS_ALLOWED_OBJECT_ACE,
    ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE: ACCESS_DENIED_OBJECT_ACE,
    ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE: SYSTEM_AUDIT_OBJECT_ACE,
    ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE: ACCESS_ALLOWED_CALLBACK_ACE,
    ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE: ACCESS_DENIED_CALLBACK_ACE,
    ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
    ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: ACCESS_DENIED_CALLBACK_OBJECT_ACE,
    ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE: SYSTEM_AUDIT_CALLBACK_ACE,
    ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
    ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE: SYSTEM_MANDATORY_LABEL_ACE,
    ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: SYSTEM_RESOURCE_ATTRIBUTE_ACE,
    ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: SYSTEM_SCOPED_POLICY_ID_ACE,
}
"""
ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE : , # reserved
ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE : ,# reserved

"""


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEHeader:
    def __init__(self):
        self.AceType = None
        self.AceFlags = None
        self.AceSize = None

    def to_buffer(self, buff):
        buff.write(self.AceType.value.to_bytes(1, 'little', signed=False))
        buff.write(self.AceFlags.to_bytes(1, 'little', signed=False))
        buff.write(self.AceSize.to_bytes(2, 'little', signed=False))

    @staticmethod
    def from_bytes(data):
        return ACEHeader.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff):
        hdr = ACEHeader()
        hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        return hdr

    @staticmethod
    def pre_parse(buff):
        pos = buff.tell()
        hdr = ACEHeader()
        hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed=False))
        hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed=False))
        hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed=False)
        buff.seek(pos, 0)
        return hdr


class ACL:
    def __init__(self, sd_object_type=None):
        self.AclRevision = None
        self.Sbz1 = 0
        self.AclSize = None
        self.AceCount = None
        self.Sbz2 = 0

        self.aces = []
        self.sd_object_type = sd_object_type

    @staticmethod
    def from_bytes(data, sd_object_type=None):
        return ACL.from_buffer(io.BytesIO(data), sd_object_type)

    @staticmethod
    def from_buffer(buff, sd_object_type=None):
        acl = ACL(sd_object_type)
        acl.AclRevision = int.from_bytes(buff.read(1), 'little', signed=False)
        acl.Sbz1 = int.from_bytes(buff.read(1), 'little', signed=False)
        acl.AclSize = int.from_bytes(buff.read(2), 'little', signed=False)
        acl.AceCount = int.from_bytes(buff.read(2), 'little', signed=False)
        acl.Sbz2 = int.from_bytes(buff.read(2), 'little', signed=False)
        for _ in range(acl.AceCount):
            acl.aces.append(ACE.from_buffer(buff, sd_object_type))
        return acl

    def to_bytes(self):
        buff = io.BytesIO()
        self.to_buffer(buff)
        buff.seek(0)
        return buff.read()

    def to_buffer(self, buff):
        data_buff = io.BytesIO()

        self.AceCount = len(self.aces)
        for ace in self.aces:
            data_buff.write(ace.to_bytes())

        self.AclSize = 8 + data_buff.tell()

        buff.write(self.AclRevision.to_bytes(1, 'little', signed=False))
        buff.write(self.Sbz1.to_bytes(1, 'little', signed=False))
        buff.write(self.AclSize.to_bytes(2, 'little', signed=False))
        buff.write(self.AceCount.to_bytes(2, 'little', signed=False))
        buff.write(self.Sbz2.to_bytes(2, 'little', signed=False))
        data_buff.seek(0)
        buff.write(data_buff.read())

    def __str__(self):
        t = '=== ACL ===\r\n'
        for ace in self.aces:
            t += '%s\r\n' % str(ace)
        return t

    def to_ssdl(self, object_type=None):
        t = ''
        for ace in self.aces:
            t += ace.to_ssdl(object_type)
        return t

    def to_string_list(self, object_type=None):
        t = []
        for ace in self.aces:
            t.append(ace.to_ssdl(object_type))
        return t

    def to_dict_list(self, object_type=None):
        t = []
        for ace in self.aces:
            t.append(ace.to_dict(object_type))
        return t


class SE_SACL(enum.IntFlag):
    SE_DACL_AUTO_INHERIT_REQ = 0x0100  # Indicates a required security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
    # For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
    SE_DACL_AUTO_INHERITED = 0x0400  # Indicates a security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
    # For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
    SE_DACL_DEFAULTED = 0x0008  # Indicates a security descriptor with a default DACL. For example, if the creator an object does not specify a DACL, the object receives the default DACL from the access token of the creator. This flag can affect how the system treats the DACL with respect to ACE inheritance. The system ignores this flag if the SE_DACL_PRESENT flag is not set.
    # This flag is used to determine how the final DACL on the object is to be computed and is not stored physically in the security descriptor control of the securable object.
    # To set this flag, use the SetSecurityDescriptorDacl function.
    SE_DACL_PRESENT = 0x0004  # Indicates a security descriptor that has a DACL. If this flag is not set, or if this flag is set and the DACL is NULL, the security descriptor allows full access to everyone.
    # This flag is used to hold the security information specified by a caller until the security descriptor is associated with a securable object. After the security descriptor is associated with a securable object, the SE_DACL_PRESENT flag is always set in the security descriptor control.
    # To set this flag, use the SetSecurityDescriptorDacl function.
    SE_DACL_PROTECTED = 0x1000  # Prevents the DACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
    SE_GROUP_DEFAULTED = 0x0002  # Indicates that the security identifier (SID) of the security descriptor group was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose security descriptor group was set by a default mechanism. To set this flag, use the SetSecurityDescriptorGroup function.
    SE_OWNER_DEFAULTED = 0x0001  # Indicates that the SID of the owner of the security descriptor was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose owner was set by a default mechanism. To set this flag, use the SetSecurityDescriptorOwner function.
    SE_RM_CONTROL_VALID = 0x4000  # Indicates that the resource manager control is valid.
    SE_SACL_AUTO_INHERIT_REQ = 0x0200  # Indicates a required security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
    # The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
    SE_SACL_AUTO_INHERITED = 0x0800  # Indicates a security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
    # The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
    SE_SACL_DEFAULTED = 0x0008  # A default mechanism, rather than the original provider of the security descriptor, provided the SACL. This flag can affect how the system treats the SACL, with respect to ACE inheritance. The system ignores this flag if the SE_SACL_PRESENT flag is not set. To set this flag, use the SetSecurityDescriptorSacl function.
    SE_SACL_PRESENT = 0x0010  # Indicates a security descriptor that has a SACL. To set this flag, use the SetSecurityDescriptorSacl function.
    SE_SACL_PROTECTED = 0x2000  # Prevents the SACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
    SE_SELF_RELATIVE = 0x8000  # Indicates a self-relative security descriptor. If this flag is not set, the security descriptor is in absolute format. For more information, see Absolute and Self-Relative Security Descriptors.


sddl_acl_control_flags = {
    "P": SE_SACL.SE_DACL_PROTECTED,
    "AR": SE_SACL.SE_DACL_AUTO_INHERIT_REQ,
    "AI": SE_SACL.SE_DACL_AUTO_INHERITED,
    # "NO_ACCESS_CONTROL" : 0
}
sddl_acl_control_flags_inv = {v: k for k, v in sddl_acl_control_flags.items()}


def sddl_acl_control(flags):
    t = ''
    for x in sddl_acl_control_flags_inv:
        if x in flags:
            t += sddl_acl_control_flags_inv[x]
    return t


# https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_security_descriptor
class SECURITY_DESCRIPTOR:
    def __init__(self, object_type=None):
        self.Revision = None
        self.Sbz1 = None
        self.Control = None
        self.Owner = None
        self.Group = None
        self.Sacl = None
        self.Dacl = None

        self.object_type = object_type  # high level info, not part of the struct

    @staticmethod
    def from_bytes(data, object_type=None):
        return SECURITY_DESCRIPTOR.from_buffer(io.BytesIO(data), object_type)

    def to_bytes(self):
        buff = io.BytesIO()
        self.to_buffer(buff)
        buff.seek(0)
        return buff.read()

    def to_buffer(self, buff):
        start = buff.tell()
        buff_data = io.BytesIO()
        OffsetOwner = 0
        OffsetGroup = 0
        OffsetSacl = 0
        OffsetDacl = 0

        if self.Owner is not None:
            buff_data.write(self.Owner.to_bytes())
            OffsetOwner = start + 20

        if self.Group is not None:
            OffsetGroup = start + 20 + buff_data.tell()
            buff_data.write(self.Group.to_bytes())

        if self.Sacl is not None:
            OffsetSacl = start + 20 + buff_data.tell()
            buff_data.write(self.Sacl.to_bytes())

        if self.Dacl is not None:
            OffsetDacl = start + 20 + buff_data.tell()
            buff_data.write(self.Dacl.to_bytes())

        buff.write(self.Revision.to_bytes(1, 'little', signed=False))
        buff.write(self.Sbz1.to_bytes(1, 'little', signed=False))
        buff.write(self.Control.to_bytes(2, 'little', signed=False))
        buff.write(OffsetOwner.to_bytes(4, 'little', signed=False))
        buff.write(OffsetGroup.to_bytes(4, 'little', signed=False))
        buff.write(OffsetSacl.to_bytes(4, 'little', signed=False))
        buff.write(OffsetDacl.to_bytes(4, 'little', signed=False))
        buff_data.seek(0)
        buff.write(buff_data.read())

    @staticmethod
    def from_buffer(buff, object_type=None):
        sd = SECURITY_DESCRIPTOR(object_type)
        sd.Revision = int.from_bytes(buff.read(1), 'little', signed=False)
        sd.Sbz1 = int.from_bytes(buff.read(1), 'little', signed=False)
        sd.Control = SE_SACL(int.from_bytes(buff.read(2), 'little', signed=False))
        OffsetOwner = int.from_bytes(buff.read(4), 'little', signed=False)
        OffsetGroup = int.from_bytes(buff.read(4), 'little', signed=False)
        OffsetSacl = int.from_bytes(buff.read(4), 'little', signed=False)
        OffsetDacl = int.from_bytes(buff.read(4), 'little', signed=False)

        if OffsetOwner > 0:
            buff.seek(OffsetOwner)
            sd.Owner = SID.from_buffer(buff)

        if OffsetGroup > 0:
            buff.seek(OffsetGroup)
            sd.Group = SID.from_buffer(buff)

        if OffsetSacl > 0:
            buff.seek(OffsetSacl)
            sd.Sacl = ACL.from_buffer(buff, object_type)

        if OffsetDacl > 0:
            buff.seek(OffsetDacl)
            sd.Dacl = ACL.from_buffer(buff, object_type)

        return sd

    def to_ssdl(self, object_type=None):
        t = 'O:' + self.Owner.to_ssdl()
        t += 'G:' + self.Group.to_ssdl()
        if self.Sacl is not None:
            t += 'S:' + self.Sacl.to_ssdl()
        if self.Dacl is not None:
            t += 'D:' + sddl_acl_control(self.Control) + self.Dacl.to_ssdl(object_type)
        return t

    def __str__(self):
        t = 'Revision: %s, ' % self.Revision
        t += 'Control: %s, ' % self.Control
        t += 'Owner: %s, ' % self.Owner
        t += 'Group: %s, ' % self.Group
        t += 'Sacl: %s, ' % self.Sacl
        t += 'Dacl: %s' % self.Dacl
        return t

#PACL = POINTER(ACL)

class TOKEN_DEFAULT_DACL(Structure):
    _fields_ = [
        ("DefaultDacl", c_void_p),#PPOINTER(ACL)
    ]

#SID TYPES
SidTypeUser             =1
SidTypeGroup            =2
SidTypeDomain           =3
SidTypeAlias            =4
SidTypeWellKnownGroup   =5
SidTypeDeletedAccount   =6
SidTypeInvalid          =7
SidTypeUnknown          =8
SidTypeComputer         =9
SidTypeLabel            =10
SidTypeLogonSession     =11