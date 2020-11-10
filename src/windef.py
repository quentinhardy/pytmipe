# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq
#Big thanks to https://raw.githubusercontent.com/rootm0s/WinPwnage/ed27ef49dc547798d110db545f3f8134f86282b4/winpwnage/core/winstructures.py
#Big thanks to https://github.com/snphive/MutateCompute/blob/7d1f4542463262b432bc96923bd87e4d694f2efa/venv/pydevd_attach_to_process/winappdbg/win32/advapi32.py

from ctypes.wintypes import *
from ctypes import *
import ctypes
import enum
import re
from windefsd import *

# Wintypes
INT = c_int
LPWSTR = c_wchar_p
LPVOID = c_void_p
LPCSTR = c_char_p
DWORD = c_uint32
SIZE_T = c_size_t
PVOID = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p
LPCTSTR = c_char_p
NTSTATUS = c_ulong
LPDWORD = POINTER(DWORD)
PULONG = POINTER(ULONG)
PHANDLE = POINTER(HANDLE)
PDWORD = POINTER(DWORD)
PSID = PVOID
SC_STATUS_TYPE = c_int
SC_ENUM_TYPE = c_int

# Misc constants
SW_HIDE = 0
SW_SHOW = 5
MAX_PATH = 260
SEE_MASK_NOCLOSEPROCESS = 0x00000040
STATUS_UNSUCCESSFUL = ULONG(0xC0000001)

# Process constants
PROCESS_QUERY_INFORMATION = 0x0400
MAXIMUM_ALLOWED = 0x02000000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = (
            0x0080 | 0x0002 | 0x0040 | 0x0400 | 0x1000 | 0x0200 | 0x0100 | 0x0800 | 0x0001 | 0x0008 | 0x0010 | 0x0020 | 0x00100000)

# Token constants
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x00000008
TOKEN_ADJUST_PRIVILEGES = 0x00000020
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ALL_ACCESS = (0x000F0000 | 0x0001 | 0x0002 | 0x0004 | 0x00000008 | 0x0010 | 0x00000020 | 0x0040 | 0x0080 | 0x0100)
TOKEN_PRIVS = (0x00000008 | (0x00020000 | 0x00000008) | 0x0004 | 0x0010 | 0x0002 | 0x0001 | (131072 | 4))
TOKEN_WRITE = (0x00020000 | 0x0020 | 0x0040 | 0x0080)
TOKEN_READ = 0x00020008
TOKEN_IMPERSONATE  = 0x00000004
TOKEN_EXECUTE      = 0x00020000
TOKEN_QUERY_SOURCE = 0x00100000

#Logon Type
LOGON32_LOGON_INTERACTIVE = 2
LOGON32_LOGON_NETWORK = 3
LOGON32_LOGON_BATCH = 4
LOGON32_LOGON_SERVICE = 5
LOGON32_LOGON_UNLOCK = 7
LOGON32_LOGON_NETWORK_CLEARTEXT = 8
LOGON32_LOGON_NEW_CREDENTIALS = 9
#others logon
LOGON32_PROVIDER_DEFAULT = 0
LOGON32_PROVIDER_WINNT35 = 1
LOGON32_PROVIDER_WINNT40 = 2
LOGON32_PROVIDER_WINNT50 = 3

#SECURITY_IMPERSONATION_LEVEL
SecurityAnonymous = 0
SecurityIdentification = 1
SecurityImpersonation = 2
SecurityDelegation = 3
SECURITY_IMPERSONATION_LEVEL_DICT = {SecurityAnonymous:'Anonymous',
                                     SecurityIdentification:'Identify',
                                     SecurityImpersonation:'Impersonate',
                                     SecurityDelegation:'delegate'}

# Token types
TokenPrimary = 1
TokenImpersonation = 2
TOKEN_TYPE_DICT = {TokenPrimary:'Primary', TokenImpersonation:'Impersonation'}

# TOKEN_INFORMATION_CLASS, used with Get/SetTokenInformation
TokenUser = 1
TokenGroups = 2
TokenPrivileges = 3
TokenOwner = 4
TokenPrimaryGroup = 5
TokenDefaultDacl = 6
TokenSource = 7
TokenType = 8
TokenImpersonationLevel = 9
TokenStatistics = 10
TokenRestrictedSids = 11
TokenSessionId = 12
TokenGroupsAndPrivileges = 13
TokenSessionReference = 14
TokenSandBoxInert = 15
TokenAuditPolicy = 16
TokenOrigin = 17
TokenElevationType = 18
TokenLinkedToken = 19
TokenElevation = 20
TokenHasRestrictions = 21
TokenAccessInformation = 22
TokenVirtualizationAllowed = 23
TokenVirtualizationEnabled = 24
TokenIntegrityLevel = 25
TokenUIAccess = 26
TokenMandatoryPolicy = 27
TokenLogonSid = 28
TokenIsAppContainer=29
TokenCapabilities=30
TokenAppContainerSid=31
TokenAppContainerNumber=32
TokenUserClaimAttributes=33
TokenDeviceClaimAttributes=34
TokenRestrictedUserClaimAttributes=35
TokenRestrictedDeviceClaimAttributes=36
TokenDeviceGroups=37
TokenRestrictedDeviceGroups=38
TokenSecurityAttributes=39
TokenIsRestricted=40
TokenProcessTrustLevel=41
TokenPrivateNameSpace=42
TokenSingletonAttributes=43
TokenBnoIsolation=44
TokenChildProcessFlags=45
TokenIsLessPrivilegedAppContainer=46
TokenIsSandboxed=47
TokenOriginatingProcessTrustLevel=48

class WELL_KNOWN_SID_TYPE(enum.IntFlag):
 WinNullSid = 0
 WinWorldSid = 1
 WinLocalSid = 2
 WinCreatorOwnerSid = 3
 WinCreatorGroupSid = 4
 WinCreatorOwnerServerSid = 5
 WinCreatorGroupServerSid = 6
 WinNtAuthoritySid = 7
 WinDialupSid = 8
 WinNetworkSid = 9
 WinBatchSid = 10
 WinInteractiveSid = 11
 WinServiceSid = 12
 WinAnonymousSid = 13
 WinProxySid = 14
 WinEnterpriseControllersSid = 15
 WinSelfSid = 16
 WinAuthenticatedUserSid = 17
 WinRestrictedCodeSid = 18
 WinTerminalServerSid = 19
 WinRemoteLogonIdSid = 20
 WinLogonIdsSid = 21
 WinLocalSystemSid = 22
 WinLocalServiceSid = 23
 WinNetworkServiceSid = 24
 WinBuiltinDomainSid = 25
 WinBuiltinAdministratorsSid = 26
 WinBuiltinUsersSid = 27
 WinBuiltinGuestsSid = 28
 WinBuiltinPowerUsersSid = 29
 WinBuiltinAccountOperatorsSid = 30
 WinBuiltinSystemOperatorsSid = 31
 WinBuiltinPrintOperatorsSid = 32
 WinBuiltinBackupOperatorsSid = 33
 WinBuiltinReplicatorSid = 34
 WinBuiltinPreWindows2000CompatibleAccessSid = 35
 WinBuiltinRemoteDesktopUsersSid = 36
 WinBuiltinNetworkConfigurationOperatorsSid = 37
 WinAccountAdministratorSid = 38
 WinAccountGuestSid = 39
 WinAccountKrbtgtSid = 40
 WinAccountDomainAdminsSid = 41
 WinAccountDomainUsersSid = 42
 WinAccountDomainGuestsSid = 43
 WinAccountComputersSid = 44
 WinAccountControllersSid = 45
 WinAccountCertAdminsSid = 46
 WinAccountSchemaAdminsSid = 47
 WinAccountEnterpriseAdminsSid = 48
 WinAccountPolicyAdminsSid = 49
 WinAccountRasAndIasServersSid = 50
 WinNTLMAuthenticationSid = 51
 WinDigestAuthenticationSid = 52
 WinSChannelAuthenticationSid = 53
 WinThisOrganizationSid = 54
 WinOtherOrganizationSid = 55
 WinBuiltinIncomingForestTrustBuildersSid = 56
 WinBuiltinPerfMonitoringUsersSid = 57
 WinBuiltinPerfLoggingUsersSid = 58
 WinBuiltinAuthorizationAccessSid = 59
 WinBuiltinTerminalServerLicenseServersSid = 60
 WinBuiltinDCOMUsersSid = 61
 WinBuiltinIUsersSid = 62
 WinIUserSid = 63
 WinBuiltinCryptoOperatorsSid = 64
 WinUntrustedLabelSid = 65
 WinLowLabelSid = 66
 WinMediumLabelSid = 67
 WinHighLabelSid = 68
 WinSystemLabelSid = 69
 WinWriteRestrictedCodeSid = 70
 WinCreatorOwnerRightsSid = 71
 WinCacheablePrincipalsGroupSid = 72
 WinNonCacheablePrincipalsGroupSid = 73
 WinEnterpriseReadonlyControllersSid = 74
 WinAccountReadonlyControllersSid = 75
 WinBuiltinEventLogReadersGroup = 76
 WinNewEnterpriseReadonlyControllersSid = 77
 WinBuiltinCertSvcDComAccessGroup = 78
 WinMediumPlusLabelSid = 79
 WinLocalLogonSid = 80
 WinConsoleLogonSid = 81
 WinThisOrganizationCertificateSid = 82
 WinApplicationPackageAuthoritySid = 83
 WinBuiltinAnyPackageSid = 84
 WinCapabilityInternetClientSid = 85
 WinCapabilityInternetClientServerSid = 86
 WinCapabilityPrivateNetworkClientServerSid = 87
 WinCapabilityPicturesLibrarySid = 88
 WinCapabilityVideosLibrarySid = 89
 WinCapabilityMusicLibrarySid = 90
 WinCapabilityDocumentsLibrarySid = 91
 WinCapabilitySharedUserCertificatesSid = 92
 WinCapabilityEnterpriseAuthenticationSid = 93
 WinCapabilityRemovableStorageSid = 94
 WinBuiltinRDSRemoteAccessServersSid = 95
 WinBuiltinRDSEndpointServersSid = 96
 WinBuiltinRDSManagementServersSid = 97
 WinUserModeDriversSid = 98
 WinBuiltinHyperVAdminsSid = 99
 WinAccountCloneableControllersSid = 100
 WinBuiltinAccessControlAssistanceOperatorsSid = 101
 WinBuiltinRemoteManagementUsersSid = 102
 WinAuthenticationAuthorityAssertedSid = 103
 WinAuthenticationServiceAssertedSid = 104
 WinLocalAccountSid = 105
 WinLocalAccountAndAdministratorSid = 106
 WinAccountProtectedUsersSid = 107
 WinCapabilityAppointmentsSid = 108
 WinCapabilityContactsSid = 109
 WinAccountDefaultSystemManagedSid = 110
 WinBuiltinDefaultSystemManagedGroupSid = 111
 WinBuiltinStorageReplicaAdminsSid = 112
 WinAccountKeyAdminsSid = 113
 WinAccountEnterpriseKeyAdminsSid = 114
 WinAuthenticationKeyTrustSid = 115
 WinAuthenticationKeyPropertyMFASid = 116
 WinAuthenticationKeyPropertyAttestationSid = 117
 WinAuthenticationFreshKeyAuthSid = 118
 WinBuiltinDeviceOwnersSid = 119

# PROC_THREAD_ATTRIBUTE_NUM
PROC_THREAD_ATTRIBUTE_NUMBER   = 0x0000FFFF
PROC_THREAD_ATTRIBUTE_THREAD   = 0x00010000  # Attribute may be used with thread creation
PROC_THREAD_ATTRIBUTE_INPUT    = 0x00020000  # Attribute is input only
PROC_THREAD_ATTRIBUTE_ADDITIVE = 0x00040000  # Attribute may be "accumulated," e.g. bitmasks, counters, etc.

ProcThreadAttributeParentProcess    = 0
ProcThreadAttributeExtendedFlags    = 1
ProcThreadAttributeHandleList       = 2
ProcThreadAttributeGroupAffinity    = 3
ProcThreadAttributePreferredNode    = 4
ProcThreadAttributeIdealProcessor   = 5
ProcThreadAttributeUmsThread        = 6
ProcThreadAttributeMitigationPolicy = 7
ProcThreadAttributeMax              = 8

PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    = ProcThreadAttributeParentProcess      |                                PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS    = ProcThreadAttributeExtendedFlags      |                                PROC_THREAD_ATTRIBUTE_INPUT | PROC_THREAD_ATTRIBUTE_ADDITIVE
PROC_THREAD_ATTRIBUTE_HANDLE_LIST       = ProcThreadAttributeHandleList         |                                PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY    = ProcThreadAttributeGroupAffinity      | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_PREFERRED_NODE    = ProcThreadAttributePreferredNode      |                                PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR   = ProcThreadAttributeIdealProcessor     | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_UMS_THREAD        = ProcThreadAttributeUmsThread          | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = ProcThreadAttributeMitigationPolicy   |                                PROC_THREAD_ATTRIBUTE_INPUT

PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE           = 0x01
PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE = 0x02
PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE         = 0x04

# Process creation flags.
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
CREATE_DEFAULT_ERROR_MODE = 0x04000000
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CREATE_PROTECTED_PROCESS = 0x00040000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
CREATE_SEPARATE_WOW_VDM = 0x00000800
CREATE_SHARED_WOW_VDM = 0x00001000
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
DEBUG_ONLY_THIS_PROCESS = 0x00000002
DEBUG_PROCESS = 0x00000001
DETACHED_PROCESS = 0x00000008
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
INHERIT_PARENT_AFFINITY = 0x00010000

#
SE_PRIVILEGE_ENABLED_BY_DEFAULT = (0x00000001)
SE_PRIVILEGE_ENABLED            = (0x00000002)
SE_PRIVILEGE_REMOVED            = (0x00000004)
SE_PRIVILEGE_USED_FOR_ACCESS    = (0x80000000)

#Services
SC_MANAGER_CONNECT             = 0x0001
SC_MANAGER_CREATE_SERVICE      = 0x0002
SC_MANAGER_ENUMERATE_SERVICE   = 0x0004
SC_MANAGER_LOCK                = 0x0008
SC_MANAGER_QUERY_LOCK_STATUS   = 0x0010
SC_MANAGER_MODIFY_BOOT_CONFIG  = 0x0020

SC_MANAGER_ALL_ACCESS = SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS | SC_MANAGER_MODIFY_BOOT_CONFIG

SERVICE_QUERY_CONFIG           = 0x0001
SERVICE_CHANGE_CONFIG          = 0x0002
SERVICE_QUERY_STATUS           = 0x0004
SERVICE_ENUMERATE_DEPENDENTS   = 0x0008
SERVICE_START                  = 0x0010
SERVICE_STOP                   = 0x0020
SERVICE_PAUSE_CONTINUE         = 0x0040
SERVICE_INTERROGATE            = 0x0080
SERVICE_USER_DEFINED_CONTROL   = 0x0100

DELETE = 0x00010000
ACCESS_SYSTEM_SECURITY = 0x01000000
WRITE_OWNER = 0x00080000
WRITE_DACL = 0x00040000
READ_CONTROL = 0x00020000

SERVICE_ALL_STANDARD_ACCESS_RIGHT = DELETE | ACCESS_SYSTEM_SECURITY | WRITE_OWNER | WRITE_DACL | READ_CONTROL

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x4000000
GENERIC_EXECUTE = 0x20000000

SERVICE_ALL_GENERIC_ACCESS_RIGHT = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE

SERVICE_ALL_ACCESS = SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL | SERVICE_ALL_STANDARD_ACCESS_RIGHT | SERVICE_ALL_GENERIC_ACCESS_RIGHT

SERVICE_WIN32_OWN_PROCESS      = 0x0010
SERVICE_INTERACTIVE_PROCESS    = 0x0100
SERVICE_DEMAND_START           = 0x0003
SERVICE_ERROR_IGNORE           = 0x0000

# CreateService() service start type
SERVICE_BOOT_START   = 0x00000000
SERVICE_SYSTEM_START = 0x00000001
SERVICE_AUTO_START   = 0x00000002
SERVICE_DEMAND_START = 0x00000003
SERVICE_DISABLED     = 0x00000004

# CreateService() error control flags
SERVICE_ERROR_IGNORE    = 0x00000000
SERVICE_ERROR_NORMAL    = 0x00000001
SERVICE_ERROR_SEVERE    = 0x00000002
SERVICE_ERROR_CRITICAL  = 0x00000003

# EnumServicesStatusEx() service state filters
SERVICE_ACTIVE    = 1
SERVICE_INACTIVE  = 2
SERVICE_STATE_ALL = 3

# SERVICE_STATUS_PROCESS.dwServiceType
SERVICE_KERNEL_DRIVER       = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
SERVICE_ADAPTER             = 0x00000004
SERVICE_RECOGNIZER_DRIVER   = 0x00000008
SERVICE_WIN32_OWN_PROCESS   = 0x00000010
SERVICE_WIN32_SHARE_PROCESS = 0x00000020
SERVICE_INTERACTIVE_PROCESS = 0x00000100

# EnumServicesStatusEx() service type filters (in addition to actual types)
SERVICE_DRIVER = 0x0000000B # SERVICE_KERNEL_DRIVER and SERVICE_FILE_SYSTEM_DRIVER
SERVICE_WIN32  = 0x00000030 # SERVICE_WIN32_OWN_PROCESS and SERVICE_WIN32_SHARE_PROCESS

# SERVICE_STATUS_PROCESS.dwCurrentState
SERVICE_STOPPED             = 0x00000001
SERVICE_START_PENDING       = 0x00000002
SERVICE_STOP_PENDING        = 0x00000003
SERVICE_RUNNING             = 0x00000004
SERVICE_CONTINUE_PENDING    = 0x00000005
SERVICE_PAUSE_PENDING       = 0x00000006
SERVICE_PAUSED              = 0x00000007

# SERVICE_STATUS_PROCESS.dwControlsAccepted
SERVICE_ACCEPT_STOP                  = 0x00000001
SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002
SERVICE_ACCEPT_SHUTDOWN              = 0x00000004
SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008
SERVICE_ACCEPT_NETBINDCHANGE         = 0x00000010
SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
SERVICE_ACCEPT_POWEREVENT            = 0x00000040
SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080
SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100

# SERVICE_STATUS_PROCESS.dwServiceFlags
SERVICE_RUNS_IN_SYSTEM_PROCESS = 0x00000001

# Service control flags
SERVICE_CONTROL_STOP                  = 0x00000001
SERVICE_CONTROL_PAUSE                 = 0x00000002
SERVICE_CONTROL_CONTINUE              = 0x00000003
SERVICE_CONTROL_INTERROGATE           = 0x00000004
SERVICE_CONTROL_SHUTDOWN              = 0x00000005
SERVICE_CONTROL_PARAMCHANGE           = 0x00000006
SERVICE_CONTROL_NETBINDADD            = 0x00000007
SERVICE_CONTROL_NETBINDREMOVE         = 0x00000008
SERVICE_CONTROL_NETBINDENABLE         = 0x00000009
SERVICE_CONTROL_NETBINDDISABLE        = 0x0000000A
SERVICE_CONTROL_DEVICEEVENT           = 0x0000000B
SERVICE_CONTROL_HARDWAREPROFILECHANGE = 0x0000000C
SERVICE_CONTROL_POWEREVENT            = 0x0000000D
SERVICE_CONTROL_SESSIONCHANGE         = 0x0000000E

# Service control accepted bitmasks
SERVICE_ACCEPT_STOP                  = 0x00000001
SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002
SERVICE_ACCEPT_SHUTDOWN              = 0x00000004
SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008
SERVICE_ACCEPT_NETBINDCHANGE         = 0x00000010
SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
SERVICE_ACCEPT_POWEREVENT            = 0x00000040
SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080
SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100
SERVICE_ACCEPT_TIMECHANGE            = 0x00000200
SERVICE_ACCEPT_TRIGGEREVENT          = 0x00000400
SERVICE_ACCEPT_USERMODEREBOOT        = 0x00000800

# enum SC_ACTION_TYPE
SC_ACTION_NONE        = 0
SC_ACTION_RESTART     = 1
SC_ACTION_REBOOT      = 2
SC_ACTION_RUN_COMMAND = 3

# QueryServiceConfig2, configuration information
SERVICE_CONFIG_DESCRIPTION     = 1
SERVICE_CONFIG_FAILURE_ACTIONS = 2
SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3
SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4
SERVICE_CONFIG_PREFERRED_NODE = 9
SERVICE_CONFIG_PRESHUTDOWN_INFO = 7
SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6
SERVICE_CONFIG_SERVICE_SID_INFO = 5
SERVICE_CONFIG_TRIGGER_INFO = 8
SERVICE_CONFIG_LAUNCH_PROTECTED = 12

SC_ENUM_PROCESS_INFO = 0

SERVICE_NO_CHANGE = 0xffffffff

#END services

#dwLogonFlags
LOGON_WITH_PROFILE = 0x00000001
LOGON_NETCREDENTIALS_ONLY = 0x00000002

# PTOKEN_ELEVATION_TYPE
TokenElevationTypeDefault   = 1
TokenElevationTypeFull      = 2
TokenElevationTypeLimited   = 3
TOKEN_ELEVATION_TYPE_DICT = {TokenElevationTypeDefault:'Default',
                            TokenElevationTypeFull:'Full',
                            TokenElevationTypeLimited:'Limited'
                             }


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/23e75ca3-98fd-4396-84e5-86cd9d40d343
OWNER_SECURITY_INFORMATION = 0x00000001 #The owner identifier of the object is being referenced.
GROUP_SECURITY_INFORMATION = 0x00000002 #The primary group identifier of the object is being referenced.
DACL_SECURITY_INFORMATION = 0x00000004 #The DACL of the object is being referenced.
SACL_SECURITY_INFORMATION = 0x00000008 #The SACL of the object is being referenced.
LABEL_SECURITY_INFORMATION = 0x00000010 #The mandatory integrity label is being referenced.
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000 #The SACL inherits access control entries (ACEs) from the parent object.
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000 #The DACL inherits ACEs from the parent object.
PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000 #The SACL cannot inherit ACEs.
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000 #The DACL cannot inherit ACEs.
ATTRIBUTE_SECURITY_INFORMATION = 0x00000020 #A SYSTEM_RESOURCE_ATTRIBUTE_ACE (section 2.4.4.15) is being referenced.
SCOPE_SECURITY_INFORMATION = 0x00000040 #A SYSTEM_SCOPED_POLICY_ID_ACE (section 2.4.4.16) is being referenced.
PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080 #Reserved.
BACKUP_SECURITY_INFORMATION = 0x00010000 #The security descriptor is being accessed for use in a backup operation.

SC_STATUS_PROCESS_INFO = 0x0

#Winerrors:
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_SERVICE_REQUEST_TIMEOUT = 1053
ERROR_BAD_LENGTH = 24
ERROR_INVALID_PARAMETER = 87

#For THREAD ACCESS
THREAD_TERMINATE=0x00000001
THREAD_SUSPEND_RESUME=0x00000002
THREAD_GET_CONTEXT=0x00000008
THREAD_SET_CONTEXT=0x00000010
THREAD_SET_INFORMATION=0x00000020
THREAD_QUERY_INFORMATION=0x00000040
THREAD_SET_THREAD_TOKEN=0x00000080
THREAD_IMPERSONATE=0x00000100
THREAD_DIRECT_IMPERSONATION=0x00000200
THREAD_SET_LIMITED_INFORMATION=0x00000400
THREAD_QUERY_LIMITED_INFORMATION=0x00000800
THREAD_ALL_ACCESS=0x001f0ffb

WELL_KNOW_SIDS = {
  'S-1-0': 'Null Authority',
  'S-1-0-0': 'Nobody',
  'S-1-1': 'World Authority',
  'S-1-1-0': 'Everyone',
  'S-1-2': 'Local Authority',
  'S-1-2-0': 'Local (Users with the ability to log in locally)',
  'S-1-2-1': 'Console Logon (Users who are logged onto the physical console)',
  'S-1-3': 'Creator Authority',
  'S-1-3-0': 'Creator Owner',
  'S-1-3-1': 'Creator Group',
  'S-1-3-2': 'Creator Owner Server',
  'S-1-3-3': 'Creator Group Server',
  'S-1-3-4': 'Owner Rights',
  'S-1-4': 'Non-unique Authority',
  'S-1-5': 'NT Authority',
  'S-1-5-1': 'Dialup',
  'S-1-5-2': 'Network',
  'S-1-5-3': 'Batch',
  'S-1-5-4': 'Interactive',
  'S-1-5-6': 'Service',
  'S-1-5-7': 'Anonymous',
  'S-1-5-8': 'Proxy',
  'S-1-5-9': 'Enterprise Domain Controllers',
  'S-1-5-10': 'Principal Self',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-12': 'Restricted Code',
  'S-1-5-13': 'Terminal Server Users',
  'S-1-5-14': 'Remote Interactive Logon',
  'S-1-5-15': 'This Organization',
  'S-1-5-17': 'This Organization (Used by the default IIS user)',
  'S-1-5-18': 'Local System',
  'S-1-5-19': 'NT Authority',
  'S-1-5-20': 'NT Authority',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
  'S-1-5-32-546': 'Guests',
  'S-1-5-32-547': 'Power Users',
  'S-1-5-32-548': 'Account Operators',
  'S-1-5-32-549': 'Server Operators',
  'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators',
  'S-1-5-32-552': 'Replicators',
  'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
  'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
  'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
  'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
  'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
  'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
  'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
  'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
  'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
  'S-1-5-32-568': 'BUILTIN\\IIS IUSRS',
  'S-1-5-32-569': 'Cryptographic Operators',
  'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
  'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
  'S-1-5-33': 'Write Restricted',
  'S-1-5-64-10': 'NTLM Authentication',
  'S-1-5-64-14': 'SChannel Authentication',
  'S-1-5-64-21': 'Digest Authentication',
  'S-1-5-80': 'NT Service',
  'S-1-5-86-1544737700-199408000-2549878335-3519669259-381336952': 'WMI (Local Service)',
  'S-1-5-86-615999462-62705297-2911207457-59056572-3668589837': 'WMI (Network Service)',
  'S-1-5-1000': 'Other Organization',
  'S-1-16-0': 'Untrusted Mandatory Level',
  'S-1-16-4096': 'Low Mandatory Level',
  'S-1-16-8192': 'Medium Mandatory Level',
  'S-1-16-8448': 'Medium Plus Mandatory Level',
  'S-1-16-12288': 'High Mandatory Level',
  'S-1-16-16384': 'System Mandatory Level',
  'S-1-16-20480': 'Protected Process Mandatory Level',
  'S-1-16-28672': 'Secure Process Mandatory Level',
}

WELL_KNOW_SIDS_INV = {v: k for k, v in WELL_KNOW_SIDS.items()}

WELL_KNOW_SIDS_RE = [
  (re.compile(r'S-1-5-[0-9-]+-500'), 'Administrator'),
  (re.compile(r'S-1-5-[0-9-]+-501'), 'Guest'),
  (re.compile(r'S-1-5-[0-9-]+-502'), 'KRBTGT'),
]

#https://docs.microsoft.com/fr-fr/windows/security/threat-protection/security-policy-settings/user-rights-assignment
PRIVILEGE_BITS = {
        "SeCreateTokenPrivilege": 0x000000002,
        "SeAssignPrimaryTokenPrivilege": 0x000000003,
        "SeLockMemoryPrivilege": 0x000000004,
        "SeIncreaseQuotaPrivilege": 0x000000005,
        "SeMachineAccountPrivilege": 0x000000006,
        "SeTcbPrivilege": 0x000000007,
        "SeSecurityPrivilege": 0x000000008,
        "SeTakeOwnershipPrivilege": 0x000000009,
        "SeLoadDriverPrivilege": 0x00000000a,
        "SeSystemProfilePrivilege": 0x00000000b,
        "SeSystemtimePrivilege": 0x00000000c,
        "SeProfileSingleProcessPrivilege": 0x00000000d,
        "SeIncreaseBasePriorityPrivilege": 0x00000000e,
        "SeCreatePagefilePrivilege": 0x00000000f,
        "SeCreatePermanentPrivilege": 0x000000010,
        "SeBackupPrivilege": 0x000000011,
        "SeRestorePrivilege": 0x000000012,
        "SeShutdownPrivilege": 0x000000013,
        "SeDebugPrivilege": 0x000000014,
        "SeAuditPrivilege": 0x000000015,
        "SeSystemEnvironmentPrivilege": 0x000000016,
        "SeChangeNotifyPrivilege": 0x000000017,
        "SeRemoteShutdownPrivilege": 0x000000018,
        "SeUndockPrivilege": 0x000000019,
        "SeSyncAgentPrivilege": 0x00000001a,
        "SeEnableDelegationPrivilege": 0x00000001b,
        "SeManageVolumePrivilege": 0x00000001c,
        "SeImpersonatePrivilege": 0x00000001d,
        "SeCreateGlobalPrivilege": 0x00000001e,
        "SeTrustedCredManAccessPrivilege": 0x00000001f,
        "SeRelabelPrivilege": 0x000000020,
        "SeIncreaseWorkingSetPrivilege": 0x000000021,
        "SeTimeZonePrivilege": 0x000000022,
        "SeCreateSymbolicLinkPrivilege": 0x000000023,
        "SeDelegateSessionUserImpersonatePrivilege": 0x000000024
    }
PRIVILEGE_BITS_INV = {v: k for k, v in PRIVILEGE_BITS.items()}

class EXTENDED_NAME_FORMAT(enum.IntFlag):
	NameUnknown = 0
	NameFullyQualifiedDN = 1
	NameSamCompatible = 2
	NameDisplay = 3
	NameUniqueId = 6
	NameCanonical = 7
	NameUserPrincipal = 8
	NameCanonicalEx = 9
	NameServicePrincipal = 10
	NameDnsDomain = 12
	NameGivenName = 13
	NameSurname = 14


class c_enum(enum.IntEnum):
    @classmethod
    def from_param(cls, obj):
        return c_int(cls(obj))


class TOKEN_INFORMATION_CLASS(c_enum):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class """
    TokenUser = 1
    TokenElevation = 20
    TokenIntegrityLevel = 25


class TOKEN_TYPE(c_enum):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type """
    TokenPrimary = 1
    TokenImpersonation = 2


class SECURITY_IMPERSONATION_LEVEL(INT):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level """
    SecurityAnonymous = 0
    SecurityIdentification = SecurityAnonymous + 1
    SecurityImpersonation = SecurityIdentification + 1
    SecurityDelegation = SecurityImpersonation + 1


class IntegrityLevel(object):
    """ https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids """
    SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000
    SECURITY_MANDATORY_LOW_RID = 0x00001000
    SECURITY_MANDATORY_MEDIUM_RID = 0x00002000
    SECURITY_MANDATORY_MEDIUM_PLUS_RID = SECURITY_MANDATORY_MEDIUM_RID + 0x100
    SECURITY_MANDATORY_HIGH_RID = 0X00003000
    SECURITY_MANDATORY_SYSTEM_RID = 0x00004000
    SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000

MAPPING_INTEGRITY_LEVEL = {
        IntegrityLevel.SECURITY_MANDATORY_UNTRUSTED_RID: u'Untrusted',
        IntegrityLevel.SECURITY_MANDATORY_LOW_RID: u'Low',
        IntegrityLevel.SECURITY_MANDATORY_MEDIUM_RID: u'Medium',
        IntegrityLevel.SECURITY_MANDATORY_MEDIUM_PLUS_RID: u'Medium high',
        IntegrityLevel.SECURITY_MANDATORY_HIGH_RID: u'High',
        IntegrityLevel.SECURITY_MANDATORY_SYSTEM_RID: u'System',
        IntegrityLevel.SECURITY_MANDATORY_PROTECTED_PROCESS_RID: u'Protected process',
    }

class GroupAttributes(object):
    """ https://msdn.microsoft.com/en-us/windows/desktop/aa379624"""
    SE_GROUP_ENABLED = 0x00000004
    SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
    SE_GROUP_INTEGRITY = 0x00000020
    SE_GROUP_INTEGRITY_ENABLED = 0x00000040
    SE_GROUP_LOGON_ID = 0xC0000000
    SE_GROUP_MANDATORY = 0x00000001
    SE_GROUP_OWNER = 0x00000008
    SE_GROUP_RESOURCE = 0x20000000
    SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010


class LUID(Structure):
    """ https://msdn.microsoft.com/en-us/windows/desktop/dd316552 """
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG)
    ]


class LUID_AND_ATTRIBUTES(Structure):
    """ https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_luid_and_attributes """
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD)
    ]

    def isEnabled(self):
        return bool(self.Attributes & SE_PRIVILEGE_ENABLED)

    def enable(self):
        self.Attributes |= SE_PRIVILEGE_ENABLED

    def getName(self):
        size = DWORD(10240)
        buf = create_unicode_buffer(size.value)
        try:
            res = LookupPrivilegeName(None, self.Luid, buf, size)
        except Exception as e:
            logging.error("Error with LookupPrivilegeName() in LUID_AND_ATTRIBUTES: {0}".format(e))
            return None
        return buf[:size.value]

    def __str__(self):
        res = self.getName()
        if self.isEnabled():
            res += ' (enabled)'
        return res


class TOKEN_PRIVILEGES(Structure):
    """
    https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
    Used by elevate_handle_inheritance module
    """
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 512)
    ]

    def getArray(self):
        arrayType = LUID_AND_ATTRIBUTES * self.PrivilegeCount
        privileges = cast(self.Privileges,POINTER(arrayType)).contents
        return privileges

    def __iter__(self):
        return iter(self.getArray())


class TOKEN_PRIVILEGES2(Structure):
    """
    https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
    Used by elevate_token_impersonation module
    """
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", DWORD * 3)
    ]


class PROC_THREAD_ATTRIBUTE_ENTRY(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute """
    _fields_ = [
        ("Attribute", DWORD),
        ("cbSize", SIZE_T),
        ("lpValue", PVOID)
    ]


class PROC_THREAD_ATTRIBUTE_LIST(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute """
    _fields_ = [
        ("dwFlags", DWORD),
        ("Size", ULONG),
        ("Count", ULONG),
        ("Reserved", ULONG),
        ("Unknown", PULONG),
        ("Entries", PROC_THREAD_ATTRIBUTE_ENTRY * 1)
    ]


class STARTUPINFO(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa """
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE)
    ]


class STARTUPINFOEX(Structure):
    """ https://msdn.microsoft.com/en-us/windows/desktop/ms686329 """
    _fields_ = [
        ("StartupInfo", STARTUPINFO),
        ("lpAttributeList", LPVOID)
    ]


class PROCESS_INFORMATION(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information """
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]


class SID_AND_ATTRIBUTES(Structure):
    """ https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/ns-ntifs-_sid_and_attributes """
    _fields_ = [
        ("Sid", LPVOID),
        ("Attributes", DWORD)
    ]

class TOKEN_SOURCE(ctypes.Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_source """
    _fields_ = (
        ('SourceName', CHAR * 8),
        ('SourceIdentifier', LUID),
    )

class TOKEN_USER(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_user """
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES)
    ]

class TOKEN_PRIMARY_GROUP(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_primary_group """
    _fields_ = [
        ('PrimaryGroup',    PSID),
    ]

class TOKEN_OWNER(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner """
    _fields_ = [
        ("Owner", LPVOID),
    ]

class TOKEN_APPCONTAINER_INFORMATION(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_appcontainer_information """
    _fields_ = [
        ("TokenAppContainer", LPVOID),
    ]

class TOKEN_LINKED_TOKEN(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_linked_token """
    _fields_ = [
        ("LinkedToken", HANDLE),
    ]

class TOKEN_MANDATORY_LABEL(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label """
    _fields_ = [
        ("Label", SID_AND_ATTRIBUTES)
    ]
'''
class TOKEN_STATISTICS(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics """
    _fields_ = [
        ("TokenId",             LUID),
        ("AuthenticationId",    LUID),
        ("ExpirationTime",      LONGLONG),  # LARGE_INTEGER
        ("TokenType",           TOKEN_TYPE),
        ("ImpersonationLevel",  SECURITY_IMPERSONATION_LEVEL),
        ("DynamicCharged",      DWORD),
        ("DynamicAvailable",    DWORD),
        ("GroupCount",          DWORD),
        ("PrivilegeCount",      DWORD),
        ("ModifiedId",          LUID),
    ]
'''

class TOKEN_ORIGIN(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_origin """
    _fields_ = [
        ("OriginatingLogonSession", LUID),
    ]

class SECURITY_ATTRIBUTES(Structure):
    """ https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85) """
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL)
    ]

LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)


class SID_IDENTIFIER_AUTHORITY(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_identifier_authority """
    _fields_ = [
        ("Value",
         BYTE * 6)
    ]


class ShellExecuteInfoW(Structure):
    """ https://docs.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow """
    _fields_ = [
        ("cbSize", DWORD),
        ("fMask", ULONG),
        ("hwnd", HWND),
        ("lpVerb", LPWSTR),
        ("lpFile", LPWSTR),
        ("lpParameters", LPWSTR),
        ("lpDirectory", LPWSTR),
        ("nShow", INT),
        ("hInstApp", HINSTANCE),
        ("lpIDList", LPVOID),
        ("lpClass", LPWSTR),
        ("hKeyClass", HKEY),
        ("dwHotKey", DWORD),
        ("hIcon", HANDLE),
        ("hProcess", HANDLE)
    ]

class SERVICE_DESCRIPTION(Structure):
    _fields_ = [
        ("lpDescription", LPWSTR),
    ]

class SERVICE_DELAYED_AUTO_START_INFO(Structure):
    _fields_ = [
        ("fDelayedAutostart", BOOL),
    ]

class SERVICE_FAILURE_ACTIONS_FLAG(Structure):
    _fields_ = [
        ("fFailureActionsOnNonCrashFailures", BOOL),
    ]

def getLastErrorMessage():
    '''
    :return:
    '''
    return WinError()

def errcheck(result, func, args):
    if result == 0:
        raise WinError()
    return result

#For services

# typedef struct _SERVICE_STATUS {
#   DWORD dwServiceType;
#   DWORD dwCurrentState;
#   DWORD dwControlsAccepted;
#   DWORD dwWin32ExitCode;
#   DWORD dwServiceSpecificExitCode;
#   DWORD dwCheckPoint;
#   DWORD dwWaitHint;
# } SERVICE_STATUS, *LPSERVICE_STATUS;
class SERVICE_STATUS(Structure):
    _fields_ = [
        ("dwServiceType",               DWORD),
        ("dwCurrentState",              DWORD),
        ("dwControlsAccepted",          DWORD),
        ("dwWin32ExitCode",             DWORD),
        ("dwServiceSpecificExitCode",   DWORD),
        ("dwCheckPoint",                DWORD),
        ("dwWaitHint",                  DWORD),
    ]
LPSERVICE_STATUS = POINTER(SERVICE_STATUS)

# typedef struct _SERVICE_STATUS_PROCESS {
#   DWORD dwServiceType;
#   DWORD dwCurrentState;
#   DWORD dwControlsAccepted;
#   DWORD dwWin32ExitCode;
#   DWORD dwServiceSpecificExitCode;
#   DWORD dwCheckPoint;
#   DWORD dwWaitHint;
#   DWORD dwProcessId;
#   DWORD dwServiceFlags;
# } SERVICE_STATUS_PROCESS, *LPSERVICE_STATUS_PROCESS;
class SERVICE_STATUS_PROCESS(Structure):
    _fields_ = SERVICE_STATUS._fields_ + [
        ("dwProcessId",                 DWORD),
        ("dwServiceFlags",              DWORD),
    ]
LPSERVICE_STATUS_PROCESS = POINTER(SERVICE_STATUS_PROCESS)

# typedef struct _ENUM_SERVICE_STATUS {
#   LPTSTR         lpServiceName;
#   LPTSTR         lpDisplayName;
#   SERVICE_STATUS ServiceStatus;
# } ENUM_SERVICE_STATUS, *LPENUM_SERVICE_STATUS;
class ENUM_SERVICE_STATUSA(Structure):
    _fields_ = [
        ("lpServiceName", LPSTR),
        ("lpDisplayName", LPSTR),
        ("ServiceStatus", SERVICE_STATUS),
    ]
class ENUM_SERVICE_STATUSW(Structure):
    _fields_ = [
        ("lpServiceName", LPWSTR),
        ("lpDisplayName", LPWSTR),
        ("ServiceStatus", SERVICE_STATUS),
    ]
LPENUM_SERVICE_STATUSA = POINTER(ENUM_SERVICE_STATUSA)
LPENUM_SERVICE_STATUSW = POINTER(ENUM_SERVICE_STATUSW)

# typedef struct _ENUM_SERVICE_STATUS_PROCESS {
#   LPTSTR                 lpServiceName;
#   LPTSTR                 lpDisplayName;
#   SERVICE_STATUS_PROCESS ServiceStatusProcess;
# } ENUM_SERVICE_STATUS_PROCESS, *LPENUM_SERVICE_STATUS_PROCESS;
class ENUM_SERVICE_STATUS_PROCESSA(Structure):
    _fields_ = [
        ("lpServiceName",        LPSTR),
        ("lpDisplayName",        LPSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]
class ENUM_SERVICE_STATUS_PROCESSW(Structure):
    _fields_ = [
        ("lpServiceName",        LPWSTR),
        ("lpDisplayName",        LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]
LPENUM_SERVICE_STATUS_PROCESSA = POINTER(ENUM_SERVICE_STATUS_PROCESSA)
LPENUM_SERVICE_STATUS_PROCESSW = POINTER(ENUM_SERVICE_STATUS_PROCESSW)

class ServiceStatus(object):
    """
    Wrapper for the L{SERVICE_STATUS} structure.
    """

    def __init__(self, raw):
        """
        @type  raw: L{SERVICE_STATUS}
        @param raw: Raw structure for this service status data.
        """
        self.ServiceType             = raw.dwServiceType
        self.CurrentState            = raw.dwCurrentState
        self.ControlsAccepted        = raw.dwControlsAccepted
        self.Win32ExitCode           = raw.dwWin32ExitCode
        self.ServiceSpecificExitCode = raw.dwServiceSpecificExitCode
        self.CheckPoint              = raw.dwCheckPoint
        self.WaitHint                = raw.dwWaitHint

    def __str__(self):
        output = []
        if self.ServiceType & SERVICE_INTERACTIVE_PROCESS:
            output.append("'Interactive service'")
        else:
            output.append("'Service'")
        if   self.CurrentState == SERVICE_CONTINUE_PENDING:
            output.append("is about to continue.")
        elif self.CurrentState == SERVICE_PAUSE_PENDING:
            output.append("is pausing.")
        elif self.CurrentState == SERVICE_PAUSED:
            output.append("is paused.")
        elif self.CurrentState == SERVICE_RUNNING:
            output.append("is running.")
        elif self.CurrentState == SERVICE_START_PENDING:
            output.append("is starting.")
        elif self.CurrentState == SERVICE_STOP_PENDING:
            output.append("is stopping.")
        elif self.CurrentState == SERVICE_STOPPED:
            output.append("is stopped.")
        return " ".join(output)

class ServiceStatusProcess(object):
    """
    Wrapper for the L{SERVICE_STATUS_PROCESS} structure.
    """

    def __init__(self, raw):
        """
        @type  raw: L{SERVICE_STATUS_PROCESS}
        @param raw: Raw structure for this service status data.
        """
        self.ServiceType             = raw.dwServiceType
        self.CurrentState            = raw.dwCurrentState
        self.ControlsAccepted        = raw.dwControlsAccepted
        self.Win32ExitCode           = raw.dwWin32ExitCode
        self.ServiceSpecificExitCode = raw.dwServiceSpecificExitCode
        self.CheckPoint              = raw.dwCheckPoint
        self.WaitHint                = raw.dwWaitHint
        self.ProcessId               = raw.dwProcessId
        self.ServiceFlags            = raw.dwServiceFlags

    def __str__(self):
        output = []
        if self.ServiceType & SERVICE_INTERACTIVE_PROCESS:
            output.append("'Interactive service'")
        else:
            output.append("'Service'")
        if   self.CurrentState == SERVICE_CONTINUE_PENDING:
            output.append("is about to continue.")
        elif self.CurrentState == SERVICE_PAUSE_PENDING:
            output.append("is pausing.")
        elif self.CurrentState == SERVICE_PAUSED:
            output.append("is paused.")
        elif self.CurrentState == SERVICE_RUNNING:
            output.append("is running.")
        elif self.CurrentState == SERVICE_START_PENDING:
            output.append("is starting.")
        elif self.CurrentState == SERVICE_STOP_PENDING:
            output.append("is stopping.")
        elif self.CurrentState == SERVICE_STOPPED:
            output.append("is stopped.")
        return " ".join(output)


class ServiceStatusEntry(object):
    """
    Service status entry returned by L{EnumServicesStatus}.
    """

    def __init__(self, raw):
        """
        @type  raw: L{ENUM_SERVICE_STATUSA} or L{ENUM_SERVICE_STATUSW}
        @param raw: Raw structure for this service status entry.
        """
        self.ServiceName             = raw.lpServiceName
        self.DisplayName             = raw.lpDisplayName
        self.ServiceType             = raw.ServiceStatus.dwServiceType
        self.CurrentState            = raw.ServiceStatus.dwCurrentState
        self.ControlsAccepted        = raw.ServiceStatus.dwControlsAccepted
        self.Win32ExitCode           = raw.ServiceStatus.dwWin32ExitCode
        self.ServiceSpecificExitCode = raw.ServiceStatus.dwServiceSpecificExitCode
        self.CheckPoint              = raw.ServiceStatus.dwCheckPoint
        self.WaitHint                = raw.ServiceStatus.dwWaitHint

    def __str__(self):
        output = []
        if self.ServiceType & SERVICE_INTERACTIVE_PROCESS:
            output.append("Interactive service")
        else:
            output.append("Service")
        if self.DisplayName:
            output.append("\"%s\" (%s)" % (self.DisplayName, self.ServiceName))
        else:
            output.append("\"%s\"" % self.ServiceName)
        if   self.CurrentState == SERVICE_CONTINUE_PENDING:
            output.append("is about to continue.")
        elif self.CurrentState == SERVICE_PAUSE_PENDING:
            output.append("is pausing.")
        elif self.CurrentState == SERVICE_PAUSED:
            output.append("is paused.")
        elif self.CurrentState == SERVICE_RUNNING:
            output.append("is running.")
        elif self.CurrentState == SERVICE_START_PENDING:
            output.append("is starting.")
        elif self.CurrentState == SERVICE_STOP_PENDING:
            output.append("is stopping.")
        elif self.CurrentState == SERVICE_STOPPED:
            output.append("is stopped.")
        return " ".join(output)

class ServiceStatusProcessEntry(object):
    """
    Service status entry returned by L{EnumServicesStatusEx}.
    """

    def __init__(self, raw):
        """
        @type  raw: L{ENUM_SERVICE_STATUS_PROCESSA} or L{ENUM_SERVICE_STATUS_PROCESSW}
        @param raw: Raw structure for this service status entry.
        """
        self.ServiceName             = raw.lpServiceName
        self.DisplayName             = raw.lpDisplayName
        self.ServiceType             = raw.ServiceStatusProcess.dwServiceType
        self.CurrentState            = raw.ServiceStatusProcess.dwCurrentState
        self.ControlsAccepted        = raw.ServiceStatusProcess.dwControlsAccepted
        self.Win32ExitCode           = raw.ServiceStatusProcess.dwWin32ExitCode
        self.ServiceSpecificExitCode = raw.ServiceStatusProcess.dwServiceSpecificExitCode
        self.CheckPoint              = raw.ServiceStatusProcess.dwCheckPoint
        self.WaitHint                = raw.ServiceStatusProcess.dwWaitHint
        self.ProcessId               = raw.ServiceStatusProcess.dwProcessId
        self.ServiceFlags            = raw.ServiceStatusProcess.dwServiceFlags

    def toDict(self):
        '''
        :return: a dict
        '''
        dict = {'ServiceName':self.ServiceName,
        'DisplayName':self.DisplayName,
        'ServiceType':self.ServiceType,
        'CurrentState':self.CurrentState,
        'ControlsAccepted':self.ControlsAccepted,
        'Win32ExitCode':self.Win32ExitCode,
        'ServiceSpecificExitCode':self.ServiceSpecificExitCode,
        'CheckPoint':self.CheckPoint,
        'WaitHint':self.WaitHint,
        'ProcessId':self.ProcessId,
        'ServiceFlags':self.ServiceFlags}
        return dict

    def __str__(self):
        output = []
        if self.ServiceType & SERVICE_INTERACTIVE_PROCESS:
            output.append("Interactive service ")
        else:
            output.append("Service ")
        if self.DisplayName:
            output.append("\"%s\" (%s)" % (self.DisplayName, self.ServiceName))
        else:
            output.append("\"%s\"" % self.ServiceName)
        if   self.CurrentState == SERVICE_CONTINUE_PENDING:
            output.append(" is about to continue")
        elif self.CurrentState == SERVICE_PAUSE_PENDING:
            output.append(" is pausing")
        elif self.CurrentState == SERVICE_PAUSED:
            output.append(" is paused")
        elif self.CurrentState == SERVICE_RUNNING:
            output.append(" is running")
        elif self.CurrentState == SERVICE_START_PENDING:
            output.append(" is starting")
        elif self.CurrentState == SERVICE_STOP_PENDING:
            output.append(" is stopping")
        elif self.CurrentState == SERVICE_STOPPED:
            output.append(" is stopped")
        if self.ProcessId:
            output.append(" at process %d" % self.ProcessId)
        output.append(".")
        return "".join(output)

class QUERY_SERVICE_CONFIG(Structure):
    _fields_ = [("ServiceType", DWORD),
                ("StartType", DWORD),
                ("ErrorControl", DWORD),
                ("BinaryPathName", LPWSTR),
                ("LoadOrderGroup", LPWSTR),
                ("TagId", DWORD),
                ("Dependencies", LPWSTR),
                ("ServiceStartName", LPWSTR),
                ("DisplayName", LPWSTR),]

    def to_dict(self):
        return dict(ServiceType=self.ServiceType, StartType=self.StartType,
                    ErrorControl=self.ErrorControl, BinaryPathName=self.BinaryPathName,
                    LoadOrderGroup=self.LoadOrderGroup, TagId=self.TagId,
                    Dependencies=self.Dependencies, ServiceStartName=self.ServiceStartName,
                    DisplayName=self.DisplayName)

LPQUERY_SERVICE_CONFIG = POINTER(QUERY_SERVICE_CONFIG)

#END services

def tokenGroups(count):
    class TOKEN_GROUPS(Structure):
        _fields_ = [('GroupCount', DWORD),
                    ('Groups', SID_AND_ATTRIBUTES * count)]
    return TOKEN_GROUPS

# https://docs.microsoft.com/en-us/windows/desktop/api/shellapi/nf-shellapi-shellexecuteexw
ShellExecuteEx = ctypes.windll.shell32.ShellExecuteExW
ShellExecuteEx.argtypes = [POINTER(ShellExecuteInfoW)]
ShellExecuteEx.restype = BOOL

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.restype = HANDLE
OpenProcess.argtypes = [DWORD, BOOL, DWORD]

#https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
OpenThread = ctypes.windll.kernel32.OpenThread
OpenThread.restype = wintypes.HANDLE
OpenThread.argtypes = (DWORD, BOOL, DWORD)

# https://docs.microsoft.com/en-us/windows/desktop/api/handleapi/nf-handleapi-closehandle
CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = [LPVOID]
CloseHandle.restype = INT
CloseHandle.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-queryfullprocessimagenamew
QueryFullProcessImageNameW = ctypes.windll.kernel32.QueryFullProcessImageNameW
QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, LPWSTR, POINTER(DWORD)]
QueryFullProcessImageNameW.restype = BOOL

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360(v=vs.85).aspx
GetLastError = ctypes.windll.kernel32.GetLastError
GetLastError.restype = DWORD

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-terminateprocess
TerminateProcess = ctypes.windll.kernel32.TerminateProcess
TerminateProcess.restype = BOOL
TerminateProcess.argtypes = [HANDLE, UINT]

# https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
WaitForSingleObject.restype = DWORD
WaitForSingleObject.argtypes = [HANDLE, DWORD]

# https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
GetExitCodeProcess = ctypes.windll.kernel32.GetExitCodeProcess
GetExitCodeProcess.restype = BOOL
GetExitCodeProcess.argtypes = [HANDLE, LPDWORD]
GetExitCodeProcess.errcheck = errcheck

# https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FToken%2FNtOpenProcessToken.html
NtOpenProcessToken = ctypes.windll.ntdll.NtOpenProcessToken
NtOpenProcessToken.restype = BOOL
NtOpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
NtOpenProcessToken.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-ntsetinformationtoken
NtSetInformationToken = ctypes.windll.ntdll.NtSetInformationToken
NtSetInformationToken.restype = NTSTATUS
NtSetInformationToken.argtypes = [HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, ULONG]

# https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-rtlallocateandinitializesid
RtlAllocateAndInitializeSid = ctypes.windll.ntdll.RtlAllocateAndInitializeSid
RtlAllocateAndInitializeSid.restype = BOOL
RtlAllocateAndInitializeSid.argtypes = [POINTER(SID_IDENTIFIER_AUTHORITY), BYTE, DWORD, DWORD, DWORD, DWORD, DWORD,
                                        DWORD, DWORD, DWORD, LPVOID]

# http://www.codewarrior.cn/ntdoc/wrk/se/NtFilterToken.htm
NtFilterToken = ctypes.windll.ntdll.NtFilterToken
NtFilterToken.restype = NTSTATUS
NtFilterToken.argtypes = [HANDLE, ULONG, LPVOID, LPVOID, LPVOID, PHANDLE]

# https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-createprocesswithlogonw
CreateProcessWithLogonW = ctypes.windll.advapi32.CreateProcessWithLogonW
CreateProcessWithLogonW.restype = BOOL
CreateProcessWithLogonW.argtypes = [LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR,
                                    POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION)]

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = HANDLE

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
OpenProcessToken.restype = c_int
OpenProcessToken.argtypes = [HANDLE, DWORD, POINTER(HANDLE)]
OpenProcessToken.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
GetCurrentProcessId = ctypes.windll.kernel32.GetCurrentProcessId
GetCurrentProcessId.restype = DWORD

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getcurrentthread
GetCurrentThread = ctypes.windll.kernel32.GetCurrentThread
GetCurrentThread.restype = HANDLE

# https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-lookupprivilegevaluew
LookupPrivilegeValue = ctypes.windll.advapi32.LookupPrivilegeValueW
LookupPrivilegeValue.restype = BOOL
LookupPrivilegeValue.argtypes = [LPWSTR, LPWSTR, POINTER(LUID)]
LookupPrivilegeValue.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
AdjustTokenPrivileges = ctypes.windll.advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.restype = BOOL
AdjustTokenPrivileges.argtypes = [HANDLE, BOOL, LPVOID, DWORD, LPVOID, POINTER(DWORD)]
AdjustTokenPrivileges.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-enumprocesses
EnumProcesses = ctypes.windll.psapi.EnumProcesses
EnumProcesses.restype = BOOL
EnumProcesses.argtypes = [LPVOID, DWORD, LPDWORD]

# https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-getprocessimagefilenamea
GetProcessImageFileName = ctypes.windll.psapi.GetProcessImageFileNameA
GetProcessImageFileName.restype = DWORD
GetProcessImageFileName.argtypes = [HANDLE, LPBYTE, DWORD]

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
InitializeProcThreadAttributeList = ctypes.windll.kernel32.InitializeProcThreadAttributeList
InitializeProcThreadAttributeList.restype = BOOL
InitializeProcThreadAttributeList.argtypes = [POINTER(PROC_THREAD_ATTRIBUTE_LIST), DWORD, DWORD, POINTER(SIZE_T)]
#InitializeProcThreadAttributeList.errcheck = errcheck          <-------------------------------------------------------------------------------------------------------------

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
UpdateProcThreadAttribute = ctypes.windll.kernel32.UpdateProcThreadAttribute
UpdateProcThreadAttribute.restype = BOOL
UpdateProcThreadAttribute.argtypes = [POINTER(PROC_THREAD_ATTRIBUTE_LIST), DWORD, DWORD, PVOID, SIZE_T, PVOID,
                                      POINTER(SIZE_T)]
UpdateProcThreadAttribute.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessw
CreateProcess = ctypes.windll.kernel32.CreateProcessW
CreateProcess.restype = BOOL
CreateProcess.argtypes = [LPCWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCWSTR, POINTER(STARTUPINFOEX),
                          POINTER(PROCESS_INFORMATION)]
CreateProcess.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-deleteprocthreadattributelist
DeleteProcThreadAttributeList = ctypes.windll.kernel32.DeleteProcThreadAttributeList
DeleteProcThreadAttributeList.restype = None
DeleteProcThreadAttributeList.argtypes = [POINTER(PROC_THREAD_ATTRIBUTE_LIST)]

# https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
#Todo : manager error with errcheck
GetTokenInformation = ctypes.windll.advapi32.GetTokenInformation
GetTokenInformation.restype = BOOL
GetTokenInformation.argtypes = [HANDLE, INT, LPVOID, DWORD, PDWORD]
#GetTokenInformation.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/sddl/nf-sddl-convertsidtostringsida
ConvertSidToStringSidA = ctypes.windll.advapi32.ConvertSidToStringSidA
ConvertSidToStringSidA.restype = BOOL
ConvertSidToStringSidA.argtypes = [LPVOID, LPVOID]
ConvertSidToStringSidA.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsidtosida
ConvertStringSidToSidA = ctypes.windll.advapi32.ConvertStringSidToSidA
ConvertStringSidToSidA.restype = BOOL
ConvertStringSidToSidA.argtypes = [LPCSTR, LPVOID]
ConvertStringSidToSidA.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
DuplicateTokenEx = ctypes.windll.advapi32.DuplicateTokenEx
DuplicateTokenEx.restype = BOOL
DuplicateTokenEx.argtypes = [HANDLE, DWORD, LPVOID, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE]
DuplicateTokenEx.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
ImpersonateLoggedOnUser = ctypes.windll.advapi32.ImpersonateLoggedOnUser
ImpersonateLoggedOnUser.restype = BOOL
ImpersonateLoggedOnUser.argtypes = [HANDLE]
ImpersonateLoggedOnUser.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-createprocesswithtokenw
CreateProcessWithToken = ctypes.windll.advapi32.CreateProcessWithTokenW
CreateProcessWithToken.restype = BOOL
CreateProcessWithToken.argtypes = [HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPCWSTR, LPCWSTR, POINTER(STARTUPINFO),
                                   POINTER(PROCESS_INFORMATION)]
ImpersonateLoggedOnUser.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-openscmanagera
OpenSCManager = ctypes.windll.advapi32.OpenSCManagerA
OpenSCManager.restype = SC_HANDLE
OpenSCManager.argtypes = [LPCSTR, LPCSTR, DWORD]

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-createservicea
CreateServiceA = ctypes.windll.advapi32.CreateServiceA
CreateServiceA.restype = SC_HANDLE
CreateServiceA.argtypes = [SC_HANDLE, LPCTSTR, LPCTSTR, DWORD, DWORD, DWORD, DWORD, LPCTSTR, LPCTSTR, LPDWORD, LPCTSTR, LPCTSTR, LPCTSTR]

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-createservicew
CreateServiceW = ctypes.windll.advapi32.CreateServiceW
CreateServiceW.restype  = SC_HANDLE
CreateServiceW.argtypes = [SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR]

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-openservicea
OpenService = ctypes.windll.advapi32.OpenServiceA
OpenService.restype = SC_HANDLE
OpenService.argtypes = [SC_HANDLE, LPCTSTR, DWORD]

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-startservicea
StartService = ctypes.windll.advapi32.StartServiceA
StartService.restype = BOOL
StartService.argtypes = [SC_HANDLE, DWORD, LPCTSTR]
StartService.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-startservicew
StartServiceW = ctypes.windll.advapi32.StartServiceW
StartServiceW.restype = BOOL
StartServiceW.argtypes = [SC_HANDLE, DWORD, LPCWSTR]
StartServiceW.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-deleteservice
DeleteService = ctypes.windll.advapi32.DeleteService
DeleteService.restype = BOOL
DeleteService.argtypes = [SC_HANDLE]
DeleteService.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice
ControlService = ctypes.windll.advapi32.ControlService
ControlService.restype = BOOL
ControlService.argtypes = [SC_HANDLE, DWORD, LPSERVICE_STATUS]
ControlService.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-closeservicehandle
CloseServiceHandle = ctypes.windll.advapi32.CloseServiceHandle
CloseServiceHandle.restype = BOOL
CloseServiceHandle.argtypes = [SC_HANDLE]
CloseServiceHandle.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
CreateThread = ctypes.windll.kernel32.CreateThread
CreateThread.restype = HANDLE
CreateThread.argtypes = [LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD]

# https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea
CreateNamedPipe = ctypes.windll.kernel32.CreateNamedPipeA
CreateNamedPipe.restype = HANDLE
CreateNamedPipe.argtypes = [LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES]

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365146(v=vs.85).aspx
ConnectNamedPipe = ctypes.windll.kernel32.ConnectNamedPipe
ConnectNamedPipe.restype = BOOL
ConnectNamedPipe.argtypes = [HANDLE, LPVOID]
ConnectNamedPipe.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-readfile
ReadFile = ctypes.windll.kernel32.ReadFile
ReadFile.restype = BOOL
ReadFile.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD, LPVOID]
#No errcheck

# https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
WriteFile = ctypes.windll.kernel32.WriteFile
WriteFile.restype = BOOL
WriteFile.argtypes = [HANDLE, LPCVOID, WORD, LPDWORD, LPVOID]
WriteFile.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
CreateFileW = ctypes.windll.kernel32.CreateFileW
CreateFileW.restype = HANDLE
CreateFileW.argtypes = [LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE]

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378618(v=vs.85).aspx
ImpersonateNamedPipeClient = ctypes.windll.advapi32.ImpersonateNamedPipeClient
ImpersonateNamedPipeClient.restype = BOOL
ImpersonateNamedPipeClient.argtypes = [HANDLE]
ImpersonateNamedPipeClient.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openthreadtoken
OpenThreadToken = ctypes.windll.advapi32.OpenThreadToken
OpenThreadToken.restype = BOOL
OpenThreadToken.argtypes = [HANDLE, DWORD, BOOL, PHANDLE]
ImpersonateNamedPipeClient.errcheck = errcheck

# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessasusera
CreateProcessAsUser = ctypes.windll.advapi32.CreateProcessAsUserA
CreateProcessAsUser.restype = BOOL
CreateProcessAsUser.argtypes = [HANDLE, LPCTSTR, LPTSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCTSTR,
                                POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION)]
CreateProcessAsUser.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
LogonUser = ctypes.windll.advapi32.LogonUserW
LogonUser.argtypes = [LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, POINTER(HANDLE)]
LogonUser.restype = BOOL
#LogonUser.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew
LookupPrivilegeName = ctypes.windll.advapi32.LookupPrivilegeNameW
LookupPrivilegeName.argtypes = [LPWSTR, POINTER(LUID),LPWSTR,POINTER(wintypes.DWORD)]
LookupPrivilegeName.restype = BOOL
LogonUser.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea
GetUserNameW = ctypes.windll.advapi32.GetUserNameW
GetUserNameW.argtypes = [LPWSTR, LPDWORD]
GetUserNameW.restype = BOOL
GetUserNameW.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsida
LookupAccountSidW = ctypes.windll.advapi32.LookupAccountSidW
LookupAccountSidW.restype = BOOL
LookupAccountSidW.argtypes = [LPWSTR, PSID, LPWSTR, PDWORD, LPWSTR, PDWORD, PDWORD]
LookupAccountSidW.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceobjectsecurity
QueryServiceObjectSecurity = ctypes.windll.advapi32.QueryServiceObjectSecurity
QueryServiceObjectSecurity.argtypes = [SC_HANDLE, DWORD, PVOID, DWORD, LPDWORD]
QueryServiceObjectSecurity.restype  = BOOL
QueryServiceObjectSecurity.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex
QueryServiceStatusEx = ctypes.windll.advapi32.QueryServiceStatusEx
QueryServiceStatusEx.argtypes = [SC_HANDLE, SC_STATUS_TYPE, PVOID, DWORD, LPDWORD]
QueryServiceStatusEx.restype  = BOOL
QueryServiceStatusEx.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexa
EnumServicesStatusExA = ctypes.windll.advapi32.EnumServicesStatusExA
EnumServicesStatusExA.restype = BOOL
EnumServicesStatusExA.argtypes = [SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD, LPSTR]
EnumServicesStatusExA.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw
EnumServicesStatusExW = ctypes.windll.advapi32.EnumServicesStatusExW
EnumServicesStatusExW.argtypes = [SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR]
EnumServicesStatusExW.restype  = BOOL
EnumServicesStatusExA.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw
ChangeServiceConfigW = ctypes.windll.advapi32.ChangeServiceConfigW
ChangeServiceConfigW.restype = BOOL
ChangeServiceConfigW.argtypes = [SC_HANDLE, DWORD, DWORD, DWORD,
                                LPCWSTR, LPCWSTR, LPDWORD,
                                LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR]
EnumServicesStatusExA.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigW
QueryServiceConfigW = ctypes.windll.advapi32.QueryServiceConfigW
QueryServiceConfigW.argtypes = [SC_HANDLE, LPQUERY_SERVICE_CONFIG, DWORD, LPDWORD]
QueryServiceConfigW.restype = BOOL
QueryServiceConfigW.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w
QueryServiceConfig2W = ctypes.windll.advapi32.QueryServiceConfig2W
QueryServiceConfig2W.argtypes = [SC_HANDLE, DWORD, PVOID, DWORD, LPDWORD]
QueryServiceConfig2W.restype = BOOL
QueryServiceConfig2W.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
RevertToSelf = windll.advapi32.RevertToSelf
RevertToSelf.argtypes = []
RevertToSelf.restype = BOOL
RevertToSelf.errcheck = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthoritycount
GetSidSubAuthorityCount             = windll.advapi32.GetSidSubAuthorityCount
GetSidSubAuthorityCount.argtypes    = [c_void_p]
GetSidSubAuthorityCount.restype     = POINTER(c_ubyte)

#https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthority
GetSidSubAuthority                  = windll.advapi32.GetSidSubAuthority
GetSidSubAuthority.argtypes         = [c_void_p, DWORD]
GetSidSubAuthority.restype          = PDWORD

# https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-istokenrestricted
IsTokenRestricted = windll.advapi32.IsTokenRestricted
IsTokenRestricted.restype = BOOL
IsTokenRestricted.argtypes = [HANDLE]

#https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
#Minimum supported client: Windows XP [desktop apps | UWP apps]
CheckTokenMembership                = windll.advapi32.CheckTokenMembership
CheckTokenMembership.restype        = BOOL
CheckTokenMembership.argtypes       = [HANDLE, PSID, POINTER(BOOL)]
CheckTokenMembership.errcheck       = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokengroups?redirectedfrom=MSDN
AdjustTokenGroups                = windll.advapi32.AdjustTokenGroups
AdjustTokenGroups.restype        = BOOL
AdjustTokenGroups.argtypes       = [HANDLE, BOOL, PVOID, DWORD, PVOID, PDWORD] #PVOID = POINTER(TOKEN_GROUPS)
#AdjustTokenGroups.errcheck       = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembershipex
try:
    #Minimum supported client: Windows 8 [desktop apps | UWP apps]
    CheckTokenMembershipEx                = windll.kernel32.CheckTokenMembershipEx
    CheckTokenMembershipEx.restype        = BOOL
    CheckTokenMembershipEx.argtypes       = [HANDLE, PSID, DWORD, POINTER(BOOL)]
    CheckTokenMembershipEx.errcheck       = errcheck
    CHECK_TOKEN_MEMBERSHIP_EX_AVAILABLE = True
except:
    #The OS is win7 or less
    CHECK_TOKEN_MEMBERSHIP_EX_AVAILABLE = False

#https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid
CreateWellKnownSid                  = windll.advapi32.CreateWellKnownSid
CreateWellKnownSid.restype          = BOOL
CreateWellKnownSid.argtypes         = [DWORD, POINTER(PSID), LPVOID, PDWORD]
CreateWellKnownSid.errcheck         = errcheck

#https://docs.microsoft.com/en-us/windows/win32/api/secext/nf-secext-getusernameexw
GetUserNameExW = windll.secur32.GetUserNameExW
GetUserNameExW.argtypes = [DWORD, LPWSTR, PULONG]
GetUserNameExW.restype = BOOLEAN

#https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamew
GetComputerNameW = windll.kernel32.GetComputerNameW
GetComputerNameW.restype = BOOL
GetComputerNameW.argtypes = [LPWSTR, LPDWORD]

#https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-isuseranadmin
IsUserAnAdmin = windll.shell32.IsUserAnAdmin
IsUserAnAdmin.restype = BOOL

#https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation
SetTokenInformation                     = windll.advapi32.SetTokenInformation
SetTokenInformation.restype             = BOOL
SetTokenInformation.argtypes            = [HANDLE, DWORD, LPVOID, DWORD]

def get_process_name(hProcess, dwFlags=0):
    dwSize = MAX_PATH
    while 1:
        lpdwSize = DWORD(dwSize)
        lpExeName = create_unicode_buffer('', lpdwSize.value + 1)
        success = QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, byref(lpdwSize))
        if success and 0 < lpdwSize.value < dwSize:
            break
        error = GetLastError()
        if error != ERROR_INSUFFICIENT_BUFFER:
            return False
        dwSize = dwSize + 256
        if dwSize > 0x1000:
            # this prevents an infinite loop in Windows 2008 when the path has spaces,
            # see http://msdn.microsoft.com/en-us/library/ms684919(VS.85).aspx#4
            return False
    return lpExeName.value

# Error Codes
ERROR_SUCCESS                    = 0
ERROR_PATH_NOT_FOUND             = 3
ERROR_ACCESS_DENIED              = 5
ERROR_INVALID_HANDLE             = 6
ERROR_INVALID_DATA               = 13
ERROR_INVALID_PARAMETER          = 87
ERROR_BROKEN_PIPE                = 109
ERROR_INSUFICIENT_BUFFER         = 122
ERROR_INVALID_NAME               = 123
ERROR_INVALID_LEVEL              = 124
ERROR_MORE_DATA                  = 234
ERROR_NO_TOKEN                   = 1008
ERROR_DEPENDENT_SERVICES_RUNNING = 1051
ERROR_INVALID_SERVICE_CONTROL    = 1052
ERROR_SERVICE_REQUEST_TIMEOUT    = 1053
ERROR_SERVICE_ALREADY_RUNNING    = 1056
ERROR_INVALID_SERVICE_ACCOUNT    = 1057
ERROR_SERVICE_DISABLED           = 1058
ERROR_CIRCULAR_DEPENDENCY        = 1059
ERROR_SERVICE_DOES_NOT_EXISTS    = 1060
ERROR_SERVICE_CANNOT_ACCEPT_CTRL = 1061
ERROR_SERVICE_NOT_ACTIVE         = 1062
ERROR_DATABASE_DOES_NOT_EXIST    = 1065
ERROR_SERVICE_LOGON_FAILURE      = 1069
ERROR_SERVICE_MARKED_FOR_DELETE  = 1072
ERROR_SERVICE_EXISTS             = 1073
ERROR_DUPLICATE_SERVICE_NAME     = 1078
ERROR_SHUTDOWN_IN_PROGRESS       = 1115
ERROR_NOT_FOUND                  = 1168

#MANDATORY_POLICY
#https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_policy
TOKEN_MANDATORY_POLICY_OFF = 0x0
TOKEN_MANDATORY_POLICY_NO_WRITE_UP = 0x1
TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN = 0x2
TOKEN_MANDATORY_POLICY_VALID_MASK = 0x3