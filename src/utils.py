# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import logging
from windef import *
from ctypes import *
import random
import string
from base64 import b64encode
import os
from ctypes.wintypes import *
import platform

def configureLogging():
    '''
    Configure le logging
    '''
    logformatNoColor = "%(levelname)-3s -: %(message)s"#%(asctime)s
    level=logging.WARNING
    formatter = logging.Formatter(logformatNoColor, datefmt=None)
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(stream)

def GetCurrentUsername():
    '''
    Return current Username
    Return None if an error

    If the current thread is impersonating another client, the GetUserName function returns the user name of the client
    that the thread is impersonating.
    If GetUserName is called from a process that is running under the "NETWORK SERVICE" account, the string returned in
    lpBuffer may be different depending on the version of Windows. On Windows XP, the "NETWORK SERVICE" string is
    returned. On Windows Vista, the “<HOSTNAME>$” string is returned.
    '''
    logging.debug("Getting current User Name with GetUserNameW()...")
    nSize = DWORD(200)
    lpBuffer = create_unicode_buffer(u'', 200)
    try:
        GetUserNameW(lpBuffer, byref(nSize))
    except Exception as e:
        logging.warning("Impossible to get current username: {0}".format(e))
        return None
    return lpBuffer.value

def getCurrentUsernameW(nameFormat=EXTENDED_NAME_FORMAT.NameSamCompatible):
    '''
    Retrieves the name of the user or other security principal associated with the calling thread.

    You can specify the format of the returned name.
    If the thread is impersonating a client, GetUserNameEx returns the name of the client.
    If GetUserName is called from a process that is running under the "NETWORK SERVICE" account, the string returned in
    lpBuffer may be different depending on the version of Windows. On Windows XP, the "NETWORK SERVICE" string is
    returned. On Windows Vista, the “<HOSTNAME>$” string is returned.
    :param nameFormat: The format of the name. This parameter is a value from the EXTENDED_NAME_FORMAT enumeration type.
                       It cannot be NameUnknown. If the user account is not in a domain, only NameSamCompatible is
                       supported.
    :return: None if an error or string
    '''
    size = ctypes.c_ulong(0)
    GetUserNameExW(nameFormat, None, byref(size))
    buffer = create_unicode_buffer(size.value)
    status = GetUserNameExW(nameFormat, buffer, byref(size))
    if status ==0:
        logging.error("Impossible to retrieve the name of the user or other security principal: {0}".format(getLastErrorMessage()))
        return None
    logging.debug("Current name of the user or other security principal for thread: {0}".format(repr(buffer.value)))
    return buffer.value

def getPIDfromName(procName, encodingFileName='utf8'):
    '''
    Return the pid with the name procName or None if an error
    :param procName: e.g. 'lsass.exe'
    :param encodingFileName: Encoding for file name comparison
    :return: pid or None if not found or an error
    '''
    logging.debug("Searching the pid of the process {0}".format(repr(procName)))
    MAX_PATH = 260
    count = 100
    while True:
        processIds = (DWORD * count)()
        cb = sizeof(processIds)
        bytesReturned = DWORD()
        if EnumProcesses(byref(processIds), cb, byref(bytesReturned)):
            if bytesReturned.value < cb:
                break
            else:
                #Increase size of processIds table
                count *= 2
    nReturned = int(bytesReturned.value/sizeof(c_ulong()))
    logging.debug("Number of pids: {0}".format(nReturned))
    for index in range(nReturned):
        processId = processIds[index]
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, processId)
        if hProcess:
            imageFileName = (ctypes.c_char * MAX_PATH)()
            if GetProcessImageFileName(hProcess, imageFileName, MAX_PATH) > 0:
                filename = os.path.basename(imageFileName.value)
                filenameString = filename.decode(encodingFileName)
                if filenameString == procName:
                    logging.debug("The process {0} has the pid {1}".format(repr(procName), processId))
                    return processId
    logging.debug("Impossible to find the process {0}".format(repr(procName)))
    return None

def getNameFromSid(sid, domain=None):
    """
    It retrieves the name of the account for this SID and the name of the first domain on which this SID is found.
    Use the domain for lookup.
    :param sid: pointer to a SID (structure)
    :param domain:  the name of the domain where the account name was found.
    :return: None if an error or dict dict e.g. {'Name': , 'Domain':, 'type':intValue}, notice name can be None
    """
    # Get size of username
    name = LPWSTR()
    cbName = DWORD(0)
    referencedDomainName = LPWSTR()
    cchReferencedDomainName = DWORD(0)
    peUse = DWORD(0)
    try:
        LookupAccountSidW(domain,
                          sid,
                          None,
                          byref(cbName),
                          None,
                          byref(cchReferencedDomainName),
                          byref(peUse))
    except Exception as e:
        #It's nbormal if an error: buffer not smal normaly
        pass
    if cbName.value <= 0 or cchReferencedDomainName.value <= 0:
        logging.warning("Impossible to get size of name with LookupAccountSidW(), case 2: {0}".format(getLastErrorMessage()))
        return None
    # Get username
    name = create_unicode_buffer(u'', cbName.value+1)
    referencedDomainName = create_unicode_buffer(u'', cchReferencedDomainName.value+1)
    try:
        LookupAccountSidW(domain,
                          sid,
                          name,
                          byref(cbName),
                          referencedDomainName,
                          byref(cchReferencedDomainName),
                          byref(peUse))
    except Exception as e:
        logging.error("Impossible to get name with LookupAccountSidW(), case 1: {0}".format(getLastErrorMessage()))
        return None
    '''
    if name.value == 'None':
        logging.error("Impossible to get name with LookupAccountSidW(), case 2: {0}".format(getLastErrorMessage()))
        return None
    '''
    return {'Name': name.value, 'Domain': referencedDomainName.value, 'type':peUse.value}

def getRandomString(size=10):
    """
    Return random string (upper and digits only)
    :param size:
    :return:
    """
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

def createNamedPipe(pipeName, openMode, pipeMode, maxInstances, defaultTimeOut=50, securityAttributes=None):
    pipeNameBytes = bytes(pipeName, encoding="utf-8")
    nOutBufferSize = 0
    nInBufferSize = 0
    pipeHandle = CreateNamedPipe(pipeNameBytes, openMode, pipeMode, maxInstances, nOutBufferSize, nInBufferSize, defaultTimeOut, securityAttributes)
    if pipeHandle == None:
        logging.error("Impossible to create the named pipe {0}: {1}".format(pipeName, get_last_error()))
        return False
    logging.debug("Successfully created Named Pipe {0}".format(repr(pipeName)))
    return pipeHandle

def readFile(handle, firstBytesOnly=False):
    '''
    If firstBytes is enabled, read first bytes only, not all data
    :param handle:
    :return: Return bytes or None if an error
    '''
    logging.debug("Getting data on given handle (firstBytesOnly == {0})".format(firstBytesOnly))
    BUFSIZE = 0x500000
    data = b""
    buf = create_string_buffer(BUFSIZE)
    bytesRead = c_uint()
    while True:
        retVal = ReadFile(handle,
                          byref(buf), sizeof(buf),
                          byref(bytesRead), None)
        if retVal:
            data += buf.raw[:bytesRead.value]
        elif GetLastError() == ERROR_MORE_DATA:
            data += buf.raw[:bytesRead.value]
        elif GetLastError() == ERROR_BROKEN_PIPE:
            logging.debug("ERROR_BROKEN_PIPE, communication stopped")
            break
        else:
            logging.error("Error reading from pipe: {0}".format(getLastErrorMessage()))
            return None
        logging.debug("Data received from handle for the moment: {0}".format(repr(data)))
        if firstBytesOnly == True:
            logging.debug("firstBytesOnly is enabled, stop getting data")
            break
    logging.debug("Data received from handle: {0}".format(repr(data)))
    return data

def encodePScode(code):
    """
    Encode the code and return the encoded code for powershell (UTF-16LE + base64)
    Can be used with powershell.exe -encodedcommand for example
    :param code:
    :return:
    """
    return b64encode(code.encode('UTF-16LE')).decode('utf-8')

def executeSystemCommand(cmd, args="", window=False):
    """
    Execute a system command on the local system with WaitForSingleObject & GetExitCodeProcess
    :return: Return Exit code or None if an error
    """
    logging.debug('Executing the command: {0} {1}'.format(cmd, args))
    shellExecInfo = ShellExecuteInfoW()
    shellExecInfo.cbSize = sizeof(shellExecInfo)
    shellExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS
    shellExecInfo.nShow = SW_SHOW if window else SW_HIDE
    shellExecInfo.lpFile = cmd
    shellExecInfo.lpParameters = args
    if ShellExecuteEx(byref(shellExecInfo)):
        WaitForSingleObject(shellExecInfo.hProcess, -1)
        exitCode = c_ulong(0)
        try:
            GetExitCodeProcess(shellExecInfo.hProcess, pointer(exitCode))
            logging.debug("Command executed. Exit Code: {0}".format(exitCode.value))
            return exitCode.value
        except Exception as e:
            logging.error("Impossible to get exit code after command execution: {0}".format(e))
            return None
    else:
        logging.error("Impossible to get exit code after command execution")
        return None

def isLocalAdminWithTest():
    """
    Naive method for checking if current process/user is really a local admin
    Try to open in RW C:\Windows\System32\drivers\etc\hosts for checking if current process if privileged
    :return:
    """
    path = os.environ['WINDIR'] + "\\System32\\drivers\\etc\\hosts"
    try:
        f= open(path, 'w+')
    except Exception as e:
        logging.debug("Impossible to open file {0} with RW: {1}".format(path, e))
        return False
    logging.debug("User can open file {0} with RW".format(path))
    return True

def getAllProcessIDs():
    '''
    Get all process IDs

    :return: (DWORD * count)(), processIds
    '''
    count = 100
    while True:
        processIds = (DWORD * count)()
        cb = sizeof(processIds)
        bytesReturned = DWORD()
        if EnumProcesses(byref(processIds), cb, byref(bytesReturned)):
            if bytesReturned.value < cb:
                break
            else:
                # Increase size of processIds table
                count *= 2
    nReturned = int(bytesReturned.value / sizeof(c_ulong()))
    return processIds, nReturned

def getLocalNetbiosName():
    '''
    Retrieves the NetBIOS name of the local computer.
    
    Name stablished at system startup, when the system reads it from the registry.
    :param self: 
    :return: string or None if an error
    '''
    lenComputerName = c_uint32()
    GetComputerNameW(None, lenComputerName)
    computerName = create_unicode_buffer(lenComputerName.value)
    status = GetComputerNameW(computerName, lenComputerName)
    if status == 0:
        logging.error("Impossible to retrieve the NetBIOS name of the local computer: {0}".format(e))
        return None
    logging.debug("Current NetBIOS name: {0}".format(repr(computerName.value)))
    return computerName.value

def is32BitsProcess():
    '''
    Return true if current process is 32 bits process.
    :return: True if 32 bits process. Otherwise false
    '''
    currentArch = platform.architecture()[0]
    logging.debug("Current process arch: {0}".format(currentArch))
    if '32' in currentArch:
        return True
    else:
        return False

def getFullCmdPath():
    '''
    Return full path to cmd.exe
    :return:
    '''
    windirPath = 'C:\Windows'
    try:
        windirPath = os.environ['WINDIR']
    except Exception as e:
        logging.error("Impossible to get WINDIR env var, set to c:\windows: {0}".format(e))
    appName = os.path.join(windirPath, 'System32', 'cmd.exe')
    return appName