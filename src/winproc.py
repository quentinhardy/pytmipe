# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq
#Thanks to https://github.com/hakbaby/PyCheat

from windef import *
from ctypes import *
from ctypes.wintypes import *

STATUS_SUCCESS                 = 0x00000000
STATUS_INFO_LENGTH_MISMATCH    = 0xc0000004
STATUS_BUFFER_OVERFLOW         = 0x80000005
INVALID_HANDLE_VALUE = -1
DUPLICATE_SAME_ACCESS = 0x00000002
DUPLICATE_CLOSE_SOURCE = 0x00000001
ObjectBasicInformation         = 0
ObjectNameInformation          = 1
ObjectTypeInformation          = 2
ObjectAllTypesInformation      = 3
ObjectHandleInformation        = 4
"""
NtQuerySystemInformation/SYSTEM_INFORMATION_CLASS
http://www.informit.com/articles/article.aspx?p=22442&seqNum=4
"""
SystemBasicInformation                  = 1     # 0x002C
SystemProcessorInformation              = 2     # 0x000C
SystemPerformanceInformation            = 3     # 0x0138
SystemTimeInformation                   = 4     # 0x0020
SystemPathInformation                   = 5     # not implemented
SystemProcessInformation                = 5    # 0x00F8 + per process
SystemCallInformation                   = 7     # 0x0018 + (n * 0x0004)
SystemConfigurationInformation          = 8     # 0x0018
SystemProcessorCounters                 = 9     # 0x0030 per cpu
SystemGlobalFlag                        = 10    # 0x0004
SystemInfo10                            = 11    # not implemented
SystemModuleInformation                 = 12    # 0x0004 + (n * 0x011C)
SystemLockInformation                   = 13    # 0x0004 + (n * 0x0024)
SystemInfo13                            = 14    # not implemented
SystemPagedPoolInformation              = 15    # checked build only
SystemNonPagedPoolInformation           = 16    # checked build only
SystemHandleInformation                 = 17    # 0x0004 + (n * 0x0010)
SystemObjectInformation                 = 18    # 0x0038+ + (n * 0x0030+)
SystemPagefileInformation               = 19    # 0x0018+ per page file
SystemInstemulInformation               = 20    # 0x0088
SystemInfo20                            = 21    # invalid info class
SystemCacheInformation                  = 22    # 0x0024
SystemPoolTagInformation                = 23    # 0x0004 + (n * 0x001C)
SystemProcessorStatistics               = 24    # 0x0000, or 0x0018 per cpu
SystemDpcInformation                    = 25    # 0x0014
SystemMemoryUsageInformation1           = 26    # checked build only
SystemLoadImage                         = 27    # 0x0018, set mode only
SystemUnloadImage                       = 28    # 0x0004, set mode only
SystemTimeAdjustmentInformation         = 29    # 0x000C, 0x0008 writeable
SystemMemoryUsageInformation2           = 30    # checked build only
SystemInfo30                            = 31    # checked build only
SystemInfo31                            = 32    # checked build only
SystemCrashDumpInformation              = 33    # 0x0004
SystemExceptionInformation              = 34    # 0x0010
SystemCrashDumpStateInformation         = 35    # 0x0008
SystemDebuggerInformation               = 36    # 0x0002
SystemThreadSwitchInformation           = 37    # 0x0030
SystemRegistryQuotaInformation          = 38    # 0x000C
SystemLoadDriver                        = 39    # 0x0008, set mode only
SystemPrioritySeparationInformation     = 40    # 0x0004, set mode only
SystemInfo40                            = 41    # not implemented
SystemInfo41                            = 42    # not implemented
SystemInfo42                            = 43    # invalid info class
SystemInfo43                            = 44    # invalid info class
SystemTimeZoneInformation               = 45    # 0x00AC
SystemLookasideInformation              = 46    # n * 0x0020
# info classes specific to Windows 2000
# WTS = Windows Terminal Server
SystemSetTimeSlipEvent                  = 47    # set mode only
SystemCreateSession                     = 48    # WTS, set mode only
SystemDeleteSession                     = 49    # WTS, set mode only
SystemInfo49                            = 50    # invalid info class
SystemRangeStartInformation             = 51    # 0x0004
SystemVerifierInformation               = 52    # 0x0068
SystemAddVerifier                       = 53    # set mode only
SystemSessionProcessesInformation       = 54    # WTS

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",          c_ushort),
        ("MaximumLength",   c_ushort),
        ("Buffer",          c_wchar_p),
    ]

    def __str__(self):
        return self.Buffer if self.Length > 0 else ''

    def __repr__(self):
        return repr(self.Buffer) if self.Length > 0 else "''"

class LARGE_INTEGER_UNION(Structure):
   _fields_ = [
      ('LowPart',  c_long),
      ('HighPart', c_ulong),
   ]

class LARGE_INTEGER(Union):
   _fields_ = [
      ('u1', LARGE_INTEGER_UNION),
      ('u2', LARGE_INTEGER_UNION),
      ('QuadPart', c_longlong),
   ]

class CLIENT_ID(Structure):
    """ https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057 """
    _fields_ = [
     ("UniqueProcess",                 c_void_p),
     ("UniqueThread",                  c_void_p)
   ]

class SYSTEM_THREAD_INFORMATION(Structure):
   _fields_ = [
      ('KernelTime',                   LARGE_INTEGER),
      ('UserTime',                     LARGE_INTEGER),
      ('CreateTime',                   LARGE_INTEGER),
      ('WaitTime',                     c_ulong),
      ('StartAddress',                 c_void_p),
      ('ClientID',                     CLIENT_ID),
      ('Priority',                     c_long),
      ('BasePriority',                 c_long),
      ('ContextSw',                    c_ulong),
      ('tstate',                       c_ulong),
      ('WaitReason',                   c_ulong)
   ]

class SYSTEM_PROCESS_INFORMATION_OLD(Structure):

    _fields_ = [
        ('NextEntryOffset',              c_ulong),
        ('NumberOfThreads',              c_ulong),
        ('Reserved1',                    ARRAY(LARGE_INTEGER, 3)),
        ('CreateTime',                   LARGE_INTEGER),
        ('UserTime',                     LARGE_INTEGER),
        ('KernelTime',                   LARGE_INTEGER),
        ('ImageName',                    UNICODE_STRING),
        ('BasePriority',                 c_long),
        ('UniqueProcessId',              HANDLE),
        ('InheritedFromUniqueProcessId', HANDLE),
        ('HandleCount',                  c_ulong), #Contains the total number of handles being used by the process in question
        ('Reserved2',                    c_byte * 4),
        ('VirtualMemoryCounters',        PVOID), #Normally, VM_COUNTERS
        ('PeakPagefileUsage',            c_ulong),
        ('PrivatePageCount',             c_ulong),
        ('IoCounters',                   PVOID), #IO_COUNTERS
        ('th',                           ARRAY(SYSTEM_THREAD_INFORMATION, 10)),
    ]
    def __str__(self):
        return "Pid: {0}, ImageName: {1}".format(self.UniqueProcessId, repr(self.ImageName))

class SYSTEM_PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("NextEntryOffset", ULONG),
        ("NumberOfThreads", ULONG),
        ("WorkingSetPrivate", LARGE_INTEGER),
        ("HardFaultCount", ULONG),
        ("NumberOfThreadsHighWatermark", ULONG),
        ("CycleTime", c_ulonglong),
        ("CreateTime", LARGE_INTEGER),
        ("UserTime", LARGE_INTEGER),
        ("KernelTime", LARGE_INTEGER),
        ("ImageName", UNICODE_STRING),
        ("BasePriority", LONG),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE),
        ("HandleCount", ULONG),
        ("SessionId", ULONG),
        ("UniqueProcessKey", c_void_p),
        ("PeakVirtualSize", c_void_p),
        ("VirtualSize", c_void_p),
        ("PageFaultCount", ULONG),
        ("PeakWorkingSetSize", c_void_p),
        ("WorkingSetSize", c_void_p),
        ("QuotaPeakPagedPoolUsage", c_void_p),
        ("QuotaPagedPoolUsage", c_void_p),
        ("QuotaPeakNonPagedPoolUsage", c_void_p),
        ("QuotaNonPagedPoolUsage", c_void_p),
        ("PagefileUsage", c_void_p),
        ("PeakPagefileUsage", c_void_p),
        ("PrivatePageCount", c_size_t),
        ("ReadOperationCount", LARGE_INTEGER),
        ("WriteOperationCount", LARGE_INTEGER),
        ("OtherOperationCount", LARGE_INTEGER),
        ("ReadTransferCount", LARGE_INTEGER),
        ("WriteTransferCount", LARGE_INTEGER),
        ("OtherTransferCount", LARGE_INTEGER),
        #('Threads', SYSTEM_THREAD_INFORMATION), #First Thread
    ]

    def __str__(self):
        return "Pid: {0}, ImageName: {1}".format(self.UniqueProcessId, repr(self.ImageName))

class PUBLIC_OBJECT_TYPE_INFORMATION(Structure):
    """Represent the PUBLIC_OBJECT_TYPE_INFORMATION on ntdll."""
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("Reserved", ULONG * 22),
    ]

class OBJECT_ATTRIBUTES(Structure):
    _fields_ = \
    [
        ('Length',                              ULONG),
        ('RootDirectory',                       HANDLE),
        ('ObjectName',                          POINTER(UNICODE_STRING)),
        ('Attributes',                          ULONG),
        ('SecurityDescriptor',                  PVOID),         # Points to type SECURITY_DESCRIPTOR
        ('SecurityQualityOfService',            PVOID),         # Points to type SECURITY_QUALITY_OF_SERVICE
    ]

#https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
NtQuerySystemInformation.restype  = NTSTATUS
NtQuerySystemInformation.argtypes = [c_ulong, c_void_p, c_ulong, POINTER(c_ulong)]

#https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
DuplicateHandle = windll.kernel32.DuplicateHandle
DuplicateHandle.argtypes = [HANDLE, HANDLE, HANDLE, POINTER(HANDLE), DWORD, BOOL, DWORD]
DuplicateHandle.restype = BOOL

#https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
NtQueryObject = windll.ntdll.NtQueryObject
NtQueryObject.argtypes = [HANDLE, DWORD, PVOID, ULONG, PULONG] #c_void_p is POINTER(PUBLIC_OBJECT_TYPE_INFORMATION)
NtQueryObject.restype = NTSTATUS

#https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryobject
ZwQueryObject = windll.ntdll.ZwQueryObject
ZwQueryObject.argtypes = [HANDLE, DWORD, PVOID, ULONG, PULONG] #c_void_p is POINTER(PUBLIC_OBJECT_TYPE_INFORMATION)
ZwQueryObject.restype = NTSTATUS

#https://docs.microsoft.com/en-us/windows/win32/devnotes/ntopenthread
NtOpenThread = windll.ntdll.NtOpenThread
NtOpenThread.argtypes = [POINTER(HANDLE), DWORD, PVOID, POINTER(CLIENT_ID)]
NtOpenThread.restype = NTSTATUS

def NtOpenThread2(ClientId, ObjectAttributes = None, DesiredAccess = THREAD_ALL_ACCESS):
    POBJECT_ATTRIBUTES = POINTER(OBJECT_ATTRIBUTES)
    PCLIENT_ID = POINTER(CLIENT_ID)
    ThreadHandle = HANDLE()

    if isinstance(ClientId, (int, HANDLE)):
        ClientId = CLIEND_ID(NtCurrentProcess, ClientId)

    ObjectAttributes = ObjectAttributes or OBJECT_ATTRIBUTES()

    Status = windll.ntdll.NtOpenThread(
                PHANDLE(ThreadHandle),
                ULONG(DesiredAccess),
                POBJECT_ATTRIBUTES(ObjectAttributes),
                PCLIENT_ID(ClientId)
            )
    if Status >= STATUS_SUCCESS:
        return ThreadHandle
    else:
        logggin.erro("{0}".format(Win32Error(Status)))
        return None

