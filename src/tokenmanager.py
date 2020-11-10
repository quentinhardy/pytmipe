# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import logging
from utils import *
from ctypes import *
from windef import *
from windefsd import *
from winproc import *

class TokenManager():
    '''
    For Managing Windows Tokens
    TODO:
    - GetTokenInformation + TokenDefaultDacl
    - idem + TokenRestrictedSids
    - idem + TokenMandatoryPolicy
    - idem + TokenCapabilities
    TODO (very less important)
    - GetTokenInformation + TokenVirtualizationAllowed
    - idem + TokenVirtualizationEnabled
    - idem + TokenUIAccess
    - idem + TokenUIAccess
    - idem + TokenUIAccess
    '''

    @staticmethod
    def closeHandle(handle):
        '''
        close handle (to token for example)

        :param hToken: handle (to token for example)
        :return: True if no error or False if an error
        '''
        try:
            CloseHandle(handle)
        except Exception as e:
            logging.warning("Impossible to close handle {0}: {1}".format(handle, e))
            return False
        return True

    @staticmethod
    def getTokenInformationTokenUser(hToken):
        '''
        Get the the user associated with the access token.

        :param hToken: A handle to access token
        :return: None if an error or TOKEN_USER structure
        '''
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                         TokenUser,
                                         c_void_p(),
                                         0,
                                         byref(infoSize))
        if status==0 or infoSize.value == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER:
                pass
            else:
                logging.error("Impossible to get size for getTokenInformationTokenUser: {0}".format(errorMessage))
                return None
        tokenInfo = TOKEN_USER()
        resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                     TokenUser,
                                     byref(tokenInfo),
                                     infoSize,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get TokenUser: {0}".format(getLastErrorMessage()))
            return None
        return tokenInfo

    @staticmethod
    def getTokenSid(hToken):
        """
        Get the the SID associated with the access token as a string.

        Retrieve SID (string - standard S-R-I-S-S… format) from Token.
        :param hToken: A handle to access token
        :return: None if an error or SID as string.
        """
        pToken_User = TokenManager.getTokenInformationTokenUser(hToken)
        if pToken_User == None:
            logging.error("Impossible to get Token information (SID)")
            return None
        sidStr = TokenManager.convertSidToStringSid(pToken_User.User.Sid)
        if sidStr == None:
            logging.error("Impossible to get Token SID with convertSidToStringSid()")
            return None
        return sidStr

    @staticmethod
    def getTokenAccountName(hToken):
        """
        Get the the account associated with the given access token as strings.

        :param hToken: Access token
        :return: None if an error. Return dict e.g. {'Name': , 'Domain':}
        """
        pToken_User = TokenManager.getTokenInformationTokenUser(hToken)
        if pToken_User == None:
            logging.error("Impossible to get Token information (SID)")
            return None
        accName = getNameFromSid(pToken_User.User.Sid)
        if accName == None:
            logging.error("Impossible to get Token SID with getNameFromSid()")
            return None
        return accName

    @staticmethod
    def getCurrentEffectiveAccountName():
        """
        Get the current effective account name for current thread.

        Use thread token if exist or process token.
        See getCurrentThreadEffectiveToken() for more details
        For example, if current process is running as Network Service, the returned value will be:
        {'Name': 'NETWORK SERVICE', 'Domain': 'NT AUTHORITY'}
        Be careful: Perhaps name and domain can be in lowercase or uppercase.
        :return: {'Name': , 'Domain':} or None if an error.
        """
        currentToken = TokenManager.getCurrentThreadEffectiveToken()
        if currentToken == None:
            return None
        accountName = TokenManager.getTokenAccountName(currentToken)
        TokenManager.closeHandle(currentToken)
        return accountName

    @staticmethod
    def getTokenInformationPrimaryGroup(hToken):
        '''
        Get the group security identifier (SID) for the access token.

        :param hToken: A handle to access token.
        :return: None if an error or TOKEN_PRIMARY_GROUP structure
        '''
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenPrimaryGroup,
                                     c_void_p(),
                                     0,
                                     byref(infoSize))
        if status == 0 or infoSize.value == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER:
                pass
            else:
                logging.error("Impossible to get size for getTokenInformationPrimaryGroup: {0}".format(errorMessage))
                return None
        tokenInfo = TOKEN_PRIMARY_GROUP()
        resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                     TokenPrimaryGroup,
                                     byref(tokenInfo),
                                     infoSize,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get TokenPrimaryGroup: {0}".format(getLastErrorMessage()))
            return None
        return tokenInfo

    @staticmethod
    def getTokenPrimaryGroupSID(hToken):
        """
        Get the group security identifier (SID) for the access token as a String.

        Retrieve SID (string - standard S-R-I-S-S… format) from Token.
        :param hToken: A handle to access token
        :return: None if an error or SID (string)
        """
        pToken = TokenManager.getTokenInformationPrimaryGroup(hToken)
        if pToken == None:
            logging.error("Impossible to get Token information (SID)")
            return None
        sidStr = TokenManager.convertSidToStringSid(pToken.PrimaryGroup)
        if sidStr == None:
            logging.error("Impossible to get Token SID with convertSidToStringSid()")
            return None
        return sidStr

    @staticmethod
    def getTokenInformationTokenOwner(hToken):
        '''
        Get the the default owner security identifier (SID) that will be applied to newly created objects.

        The SID is one of the user or group SIDs already in the token.
        :param hToken: A handle to access token
        :return: None if an error or TOKEN_OWNER structure
        '''
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenOwner,
                                     c_void_p(),
                                     0,
                                     byref(infoSize))
        if status == 0 or infoSize.value == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER:
                pass
            else:
                logging.error("Impossible to get size for getTokenInformationTokenOwner: {0}".format(errorMessage))
                return None
        tokenInfo = TOKEN_OWNER()
        resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                     TokenOwner,
                                     byref(tokenInfo),
                                     infoSize,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get TokenOwner: {0}".format(getLastErrorMessage()))
            return None
        return tokenInfo

    @staticmethod
    def getTokenOwnerSid(hToken):
        """
        Get the the default owner security identifier (SID) that will be applied to newly created objects (as String).

        Retrieve SID (string - standard S-R-I-S-S… format) from Token.
        :param hToken: A handle to access token
        :return: None if an error or SID as string
        """
        pToken_User = TokenManager.getTokenInformationTokenOwner(hToken)
        if pToken_User == None:
            logging.error("Impossible to get Token information (SID)")
            return None
        sidStr = TokenManager.convertSidToStringSid(pToken_User.Owner)
        if sidStr == None:
            logging.error("Impossible to get Token SID with convertSidToStringSid()")
            return None
        return sidStr

    @staticmethod
    def getTokenInformationTokenLinkedToken(hToken):
        '''
        Get the handle to the linked token of the given token.

        :param hToken: A handle to primary access token
        :return: None if an error or an handle to the token (HANDLE)
        '''
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenLinkedToken,
                                     c_void_p(),
                                     0,
                                     byref(infoSize))
        if status == 0 or infoSize.value == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER or errorMessage.winerror == ERROR_BAD_LENGTH:
                pass
            else:
                logging.error("Impossible to get size for getTokenInformationTokenLinkedToken: {0}".format(errorMessage))
                return None
        tokenInfo = TOKEN_LINKED_TOKEN()
        resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                     TokenLinkedToken,
                                     byref(tokenInfo),
                                     infoSize,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get TokenLinkedToken: {0}".format(getLastErrorMessage()))
            return None
        return tokenInfo.LinkedToken

    @staticmethod
    def getTokenInformationTokenDefaultDacl(hToken):
        '''
        Get default DACL for newly created objects.

        :param hToken: A handle to access token
        :return: None if an error or ACL object
        '''
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenDefaultDacl,
                                     c_void_p(),
                                     0,
                                     byref(infoSize))
        if status == 0 or infoSize.value == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER or errorMessage.winerror == ERROR_BAD_LENGTH:
                pass
            else:
                logging.error(
                    "Impossible to get size for getTokenInformationTokenDefaultDacl: {0}".format(errorMessage))
                return None
        tokenInfo = TOKEN_DEFAULT_DACL()
        resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                     TokenDefaultDacl,
                                     byref(tokenInfo),
                                     infoSize,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get TokenDefaultDacl: {0}".format(getLastErrorMessage()))
            return None
        buff = string_at(tokenInfo.DefaultDacl, infoSize.value)
        dacl = ACL.from_bytes(buff, SE_OBJECT_TYPE.SE_KERNEL_OBJECT) #Token type
        return dacl

    @staticmethod
    def getTokenDefaultDacl(hToken):
        """
        Get default DACL for newly created objects and return a list of string.

        :param hToken: handle to Access token
        :return: None if an error or list of string
        """
        dacl = TokenManager.getTokenInformationTokenDefaultDacl(hToken)
        if dacl == None:
            return None
        else:
            return dacl.to_dict_list()

    @staticmethod
    def getTokenInformationTokenAppContainerSid(hToken):
        '''
        Get all the information in a token that is necessary for an app container.

        If the token is not associated with an app container, the TokenAppContainer member of the
        TOKEN_APPCONTAINER_INFORMATION structure points to NULL.
        Minimum supported client: Windows 8 [desktop apps only]
        Minimum supported server: Windows Server 2012 [desktop apps only]
        Returns None if before windows 8.
        :param hToken: A handle to access token
        :return: None if an error or TOKEN_APPCONTAINER_INFORMATION structure.
        '''
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenAppContainerSid,
                                     c_void_p(),
                                     0,
                                     byref(infoSize))
        if status == 0 or infoSize.value == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER or errorMessage.winerror == ERROR_BAD_LENGTH:
                pass
            elif errorMessage.winerror == ERROR_INVALID_PARAMETER:
                return None
            else:
                logging.error("Impossible to get size for getTokenInformationTokenAppContainerSid: {0}".format(errorMessage))
                return None
        tokenInfo = TOKEN_APPCONTAINER_INFORMATION()
        resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                     TokenAppContainerSid,
                                     byref(tokenInfo),
                                     infoSize,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get TokenAppContainerSid: {0}".format(getLastErrorMessage()))
            return None
        return tokenInfo

    @staticmethod
    def getTokenInformationAppContainerSid(hToken):
        """
        Get SID in a token that is necessary for an app container.

        Retrieve SID (string - standard S-R-I-S-S… format) from Token.
        Also named "Package SID"
        :return: None if an error or not defined or SID as a String.
        """
        pToken = TokenManager.getTokenInformationTokenAppContainerSid(hToken)
        if pToken == None:
            logging.debug("Impossible to get Token information for Container SID. Perhaps before Windows 8.")
            return None
        if pToken.TokenAppContainer == None:
            logging.debug("The token is not associated with an app container")
            return None
        sidStr = TokenManager.convertSidToStringSid(pToken.TokenAppContainer)
        if sidStr == None:
            logging.error("Impossible to get Token SID with convertSidToStringSid()")
            return None
        return sidStr


    @staticmethod
    def isAppContainerToken(hToken):
        '''
        Return True if it is an app container token.

        Notice: "Any callers who check the TokenIsAppContainer and have it return 0 should also verify that the caller
        token is not an identify level impersonation token. If the current token is not an app container but is an
        identity level token, you should return AccessDenied."
        Minimum supported client: Windows 8 [desktop apps only]
        Minimum supported server: Windows Server 2012 [desktop apps only]
        Returns False if before windows 8.
        :param hToken: A handle to access token
        :return: None if an error or True or False
        '''
        tokenInfo = DWORD(4)
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenIsAppContainer,
                                     byref(tokenInfo),
                                     4,
                                     byref(infoSize))
        if status == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INVALID_PARAMETER:
                return False
            else:
                logging.error("Impossible to check isAppContainerToken(): {0}".format(errorMessage))
                return None
        else:
            status = tokenInfo.value
            if status > 0:
                return True
            elif TokenManager.getTokenInformationTokenImpersonationLevel(hToken) == SecurityIdentification:
                logging.debug("Token is not an app container token but a identification token")
                return None
            else:
                return False

    @staticmethod
    def isTokenHasRestrictions(hToken):
        '''
        Return True if token has ever been filtered/restricted
        This value is valid starting with Windows Vista.
        :param hToken: A handle to access token
        :return: None if an error or True or False
        '''
        tokenInfo = DWORD(4)
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenHasRestrictions,
                                     byref(tokenInfo),
                                     4,
                                     byref(infoSize))
        if status == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INVALID_PARAMETER:
                return False
            else:
                logging.error("Impossible to check isTokenHasRestrictions(): {0}".format(errorMessage))
                return None
        else:
            status = tokenInfo.value
            if status == 0:
                return False
            else:
                return True

    @staticmethod
    def getTokenInformationTokenAppContainerNumber(hToken):
        '''
        Return the app container number for the token.

        An AppContainerNumber is a transient DWORD used to distinguish between AppContainers.
        However, it should not be used as an identity for the AppContainer.
        Minimum supported client: Windows 8 [desktop apps only]
        Minimum supported server: Windows Server 2012 [desktop apps only]
        Returns 0 if before windows 8.
        :param hToken: A handle to access token
        :return: None if an error or app container number (int)
        '''
        tokenInfo = DWORD(4)
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenAppContainerNumber,
                                     byref(tokenInfo),
                                     4,
                                     byref(infoSize))
        if status == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INVALID_PARAMETER:
                return 0
            else:
                logging.error("Impossible to get getTokenInformationTokenAppContainerNumber: {0} (1)".format(getLastErrorMessage()))
                return None
        else:
            return tokenInfo.value

    @staticmethod
    def getTokenInformationTokenElevationType(hToken):
        '''
        Get the elevation level of the token.

        Return TokenElevationType i.e. either TokenElevationTypeDefault, TokenElevationTypeFull, or
        TokenElevationTypeLimited.
        If TokenElevationTypeLimited, there is a linked token.
        :param hToken: A handle to access token
        :return: None if an error or TokenElevationType (int)
        '''
        tokenInfo = DWORD(4)
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenElevationType,
                                     byref(tokenInfo),
                                     4,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get getTokenInformationTokenElevationType: {0}".format(getLastErrorMessage()))
            return None
        else:
            return tokenInfo.value

    @staticmethod
    def getTokenInformationTokenElevation(hToken):
        '''
        Return True if token has elevated privileges (is elevated). Otherwise False.

        Uses the TOKEN_ELEVATION structure that specifies whether the token is elevated.
        A handle to access token
        :param hToken: A handle to access token
        :return: None if an error or True or False.
        '''
        tokenInfo = DWORD(4)
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenElevation,
                                     byref(tokenInfo),
                                     4,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get getTokenInformationTokenElevation: {0}".format(getLastErrorMessage()))
            return None
        else:
            if tokenInfo.value != 0:
                return True
            else:
                return False

    @staticmethod
    def getTokenInformationTokenMandatoryPolicy(hToken):
        '''
        Return the token's mandatory integrity policy.

        Valid starting with Windows Vista.
        :param hToken: A handle to access token
        :return: None if an error or integrity policy (int).
        '''
        tokenInfo = DWORD(4)
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenMandatoryPolicy,
                                     byref(tokenInfo),
                                     4,
                                     byref(infoSize))
        if status == 0:
            logging.error("Impossible to get getTokenInformationTokenMandatoryPolicy: {0}".format(getLastErrorMessage()))
            return None
        else:
            return tokenInfo.value

    @staticmethod
    def getTokenInformationTokenSource(hToken):
        '''
        Get the source of the token.

        Token source is used to distinguish between such sources as Session Manager, LAN Manager, and RPC Server.
        A string, rather than a constant, is used to identify the source so users and developers can make extensions to
        the system, such as by adding other networks, that act as the source of access tokens.
        TOKEN_QUERY_SOURCE access is needed to retrieve this information.
        :param hToken: A handle to access token
        :return: None if an error or TOKEN_SOURCE structure
        '''
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenSource,
                                     c_void_p(),
                                     0,
                                     byref(infoSize))
        if status == 0 or infoSize.value == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER:
                pass
            else:
                logging.warning("Impossible to get size for getTokenInformationTokenSource: {0}".format(errorMessage))
                return None
        tokenInfo = TOKEN_SOURCE()
        resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                     TokenSource,
                                     byref(tokenInfo),
                                     infoSize,
                                     byref(infoSize))
        if status == 0:
            logging.warning("Impossible to get getTokenInformationTokenSource: {0}".format(getLastErrorMessage()))
            return None
        return tokenInfo

    @staticmethod
    def getTokenSourceName(hToken):
        """
        Retrieve Token source name as string.

        :param hToken: A handle to access token
        :return: None if an error or string.
        """
        source = TokenManager.getTokenInformationTokenSource(hToken)
        if source == None:
            logging.debug("Impossible to get Token source name")
            return None
        return source.SourceName

    @staticmethod
    def convertSidToStringSid(sid):
        '''
        Converts a security identifier (SID) to a string format suitable for display, storage, or transmission.

        ConvertSidToStringSidA() is used to convert.
        https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtos
        :param sid: SID structure (not a String)
        :return: None if an error or SID (standard S-R-I-S-S… format as string)
        '''
        pStringSid = LPSTR()
        if not sid:
            logging.error("Sid is set to None for convertSidToStringSid()")
            return None
        try:
            ConvertSidToStringSidA(sid, byref(pStringSid))
        except Exception as e:
            logging.error("impossible to convert SID to string: {0}".format(e))
            return None
        sidStr = (pStringSid.value).decode('utf-8')
        return sidStr

    @staticmethod
    def duplicateToken(hToken,
                       impersonationLevel=SecurityImpersonation,
                       desiredAccess=TOKEN_ALL_ACCESS,
                       tokenType=TokenPrimary,
                       tokenAttributes=None):
        '''
        Creates a new access token that duplicates an existing token.
        This function can create either a primary token or an impersonation token.

        Remark 1: The DuplicateTokenEx function allows you to create a primary token that you can use in the
        CreateProcessAsUser function. This allows a server application that is impersonating a client to create a
        process that has the security context of the client. Note that the DuplicateToken function can create only
        impersonation tokens, which are not valid for CreateProcessAsUser.
        Remark 2: To set the owner in the security descriptor for the new token, the caller's process token must
        have the SE_RESTORE_NAME privilege set (lpTokenAttributes).
        :param hToken: A handle to an access token opened with TOKEN_DUPLICATE access.
        :param impersonationLevel: One of win32security.Security* values
                        https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level
        :param desiredAccess: Type of access required for the handle, combination of win32security.TOKEN_* flags
                              To request the same access rights as the existing token, specify zero. To request all
                              access rights that are valid for the caller, specify MAXIMUM_ALLOWED.
        :param tokenType: TokenPrimary or TokenImpersonation for new token
        :param tokenAttributes: Specifies security and inheritance for the new handle. None results in default DACL and
                                no inheritance,
        :return: Return hToken duplicated or None if an error
        '''
        logging.debug("Duplicating token...")
        hTokendupe = HANDLE(c_void_p(-1).value)
        try:
            DuplicateTokenEx(hToken,
                             desiredAccess,
                             tokenAttributes,
                             impersonationLevel,
                             tokenType,
                             byref(hTokendupe))
        except Exception as e:
            logging.error("Impossible to DuplicateTokenEx in duplicateToken(): {0}".format(e))
            return None
        logging.debug("Token duplicated")
        return hTokendupe

    @staticmethod
    def getCurrentProcessToken(desiredAccess=TOKEN_ALL_ACCESS):
        """
        Get the current process token (primary token only).

        :param desiredAccess: Specifies an access mask that specifies the requested types of access to the access token
        :return: None if an error or an handle to the token.
        """
        hToken = HANDLE(c_void_p(-1).value)
        try:
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, byref(hToken))
        except Exception as e:
            logging.error("Impossible to Open current Process Token for getCurrentProcessToken(): {0}".format(e))
            return None
        return hToken

    @staticmethod
    def getObjectInfo(hObject, objectInfoClass=ObjectTypeInformation, loggingOnError=False):
        '''
        To retrieve various kinds of object information.

        NtQueryObject() is used to retrieve information.
        Notice: 'ObjectTypeInformation' only is implemented for the moment. It returns a PUBLIC_OBJECT_BASIC_INFORMATION
        structure.
        #More details https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
        :param hObject: handle to object
        :param objectInfoClass: One of the following values, as enumerated in OBJECT_INFORMATION_CLASS, indicating
                                      the kind of object information to be retrieved.: ObjectTypeInformation or
                                      ObjectBasicInformation. ObjectTypeInformation only for the moment
        :param loggingOnError: print error message on debug output if disable. Otherwise stderr if enable.
        :return: None if an error or PUBLIC_OBJECT_BASIC_INFORMATION structure
        '''
        theClass = None
        if objectInfoClass == ObjectTypeInformation:
            theClass = PUBLIC_OBJECT_TYPE_INFORMATION
        else:
            logging.critical("objectTypeInformation {0} is not implemented in getObjectInfo()".format(objectTypeInfo))
            return None
        buffer = theClass()
        bufferSize = DWORD(sizeof(buffer))
        length = DWORD(0)
        status = NtQueryObject(hObject, objectInfoClass, byref(buffer), 0, length)
        #check size randomly, because sometimes the value returned it too big for allocation after.
        if length.value > 9876:
            msge = "Impossible to get size with objectTypeInformation in getObjectInfo(): {0}".format(length.value)
            if loggingOnError == True:
                logging.error(msge)
            else:
                logging.debug(msge)
            return None
        buffer = create_string_buffer(length.value)
        status = NtQueryObject(hObject, objectInfoClass, byref(buffer), length.value, length)
        if status >= STATUS_SUCCESS:
            value = str(cast(buffer, POINTER(theClass)).contents.Name)
            return value
        else:
            logging.error("Impossible to get a result with NtQueryObject(): {0}".format(getLastErrorMessage()))
            return None

    @staticmethod
    def getProcessTokenOfPid(pid, tokenAcess=TOKEN_QUERY, loggingOnError=True):
        '''
        Get the process token from PID.

        Request a handle to the targeted token with this specified pid.
        :param pid: pid of the process
        :param tokenAcess: an access mask that specifies the requested types of access to the access token.
        :param loggingOnError: print error message on debug oputput if disable.
        :return: None if an error or handle to token of process
        TODO: OpenProcess with MAXIMUM_ALLOWED or PROCESS_QUERY_INFORMATION ?
        '''
        #PROCESS_QUERY_INFORMATION according to
        #https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        hProcess = OpenProcess(MAXIMUM_ALLOWED, False, pid)#PROCESS_QUERY_INFORMATION
        if hProcess == 0 or hProcess == None:
            if loggingOnError == True:
                logging.error("Impossible to Open Process for MAXIMUM_ALLOWED on pid {0}: {1}".format(pid, getLastErrorMessage()))
            else:
                logging.debug("Impossible to Open Process for MAXIMUM_ALLOWED on pid {0}: {1}".format(pid, getLastErrorMessage()))
            return None
        hToken = HANDLE(c_void_p(-1).value)
        try:
            OpenProcessToken(hProcess, tokenAcess, byref(hToken))
        except Exception as e:
            if loggingOnError == True:
                logging.error("Impossible to Open Process Token for OpenProcessToken for {1}: {0}".format(e, tokenAcess))
            else:
                logging.debug("Impossible to Open Process Token for OpenProcessToken for {1}: {0}".format(e, tokenAcess))
            TokenManager.closeHandle(hProcess)
            return None
        TokenManager.closeHandle(hProcess)
        logging.debug("Primary token got on pid {0} with {1}".format(pid, tokenAcess))
        return hToken

    @staticmethod
    def getTokenInformationTokenImpersonationLevel(hToken, loggingOnError=True):
        """
        Return the Token impersonation level.

        :param hToken: A handle to impersonation access token
        :param loggingOnError: print error message on debug oputput if disable.
        :return: None if an error. Otherwise returns SecurityAnonymous, SecurityIdentification, SecurityImpersonation or
                 SecurityDelegation
        """
        buf = create_string_buffer(0)
        dwSize = DWORD(0)
        pStringSid = LPSTR()
        GetTokenInformation(hToken, TokenImpersonationLevel, byref(buf), 0, byref(dwSize))
        if dwSize == 0:
            if loggingOnError == True:
                logging.error("Impossible to get size before getting ImpersonationLevel: {0}".format(GetLastError()))
            else:
                logging.debug("Impossible to get size before getting ImpersonationLevel: {0}".format(GetLastError()))
            return None
        buf = create_string_buffer(dwSize.value)
        GetTokenInformation(hToken, TokenImpersonationLevel, byref(buf), dwSize.value, byref(dwSize))
        if dwSize == 0:
            if loggingOnError == True:
                logging.error("Impossible to get ImpersonationLevel: {0}".format(GetLastError()))
            else:
                logging.debug("Impossible to get ImpersonationLevel: {0}".format(GetLastError()))
            return None
        impersonationLevel = cast(buf, POINTER(DWORD)).contents.value
        if impersonationLevel < 0 or impersonationLevel>SecurityDelegation:
            if loggingOnError == True:
                logging.error("Impossible to get ImpersonationLevel, bad int: {0}".format(impersonationLevel))
            else:
                logging.debug("Impossible to get ImpersonationLevel, bad int: {0}".format(impersonationLevel))
            return None
        return impersonationLevel

    @staticmethod
    def isSystemToken(hToken):
        '''
        Return True if the Token is "nt authority\SYSTEM"

        Use the SID (owner) of the TOKEN.
        :param token: A handle to access token
        :return: Return True of False. Return None if an error.
        '''
        sid = TokenManager.getTokenSid(hToken)
        if sid == None:
            return None
        if sid == WELL_KNOW_SIDS_INV['Local System']:
            return True
        else:
            return False

    @staticmethod
    def getTokenInformationTokenType(hToken):
        """
        Return the Token Type, either primary or impersonation token.

        :param hToken: A handle to access token
        :return: None if an error or TokenPrimary (int) or TokenImpersonation (int)
        """
        # Call with zero length to determine what size buffer
        buffer = create_string_buffer(0)
        returnLength = DWORD(0)
        try:
            res = GetTokenInformation(hToken, TokenType, byref(buffer), 0, returnLength)
        except Exception as e:
            logging.error("Impossible to get size before getting token type: {0}".format(e))
            return None
        # Get value
        buffer = create_string_buffer(returnLength.value)
        try:
            res = GetTokenInformation(hToken,
                                      TokenType,
                                      byref(buffer),
                                      returnLength.value,
                                      returnLength)
        except Exception as e:
            logging.error("Impossible to get token type: {0}".format(e))
            return None
        tokenType = cast(buffer, POINTER(DWORD)).contents.value
        if tokenType == TokenPrimary:
            logging.debug("Token is TokenPrimary")
            return TokenPrimary
        elif tokenType == TokenImpersonation:
            logging.debug("Token is TokenImpersonation")
            return TokenImpersonation
        else:
            logging.error("Token type unknown: {0}".format(tokenType))
            return None

    @staticmethod
    def getTokenInformationTokenIntegrityLevel(hToken):
        '''
        Get the mandatory integrity level for the token.

        :param hToken: A handle to access token
        :return: None if an error or TOKEN_MANDATORY_LABEL strucuture.
        '''
        infoSize = DWORD()
        status= GetTokenInformation(hToken,
                                    TokenIntegrityLevel,
                                    c_void_p(),
                                    infoSize,
                                    byref(infoSize))
        if infoSize.value == 0 or status==0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER:
                pass
            else:
                logging.error("Impossible to get size for TokenIntegrityLevel: {0}".format(errorMessage))
                return None
        tokenInfo = TOKEN_MANDATORY_LABEL()
        resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                    TokenIntegrityLevel,
                                    byref(tokenInfo),
                                    infoSize,
                                    byref(infoSize))
        if status == 0:
            logging.error("Impossible to get TokenIntegrityLevel: {0}".format(getLastErrorMessage()))
            return None
        return tokenInfo

    @staticmethod
    def getTokenInformationTokenPrivileges(hToken):
        """
        Get all privileges associated with the token.

        :param hToken: A handle to access token
        :return: None if an error or TOKEN_PRIVILEGES structure.
        """
        # Call with zero length to determine what size buffer
        returnLength = DWORD()
        res = GetTokenInformation(hToken,
                                      TokenPrivileges,
                                      None,
                                      0,
                                      returnLength)
        if returnLength == 0:
            logging.error("Impossible to get size before getting privilege information: {0}".format(GetLastError()))
            return None
        # Get data
        buffer = create_string_buffer(returnLength.value)
        res = GetTokenInformation(hToken,
                                      TokenPrivileges,
                                      byref(buffer),
                                      returnLength.value,
                                      returnLength)
        if returnLength == 0:
            logging.error("Impossible to get privilege information: {0}".format(e))
            return None
        privileges = ctypes.cast(buffer, POINTER(TOKEN_PRIVILEGES)).contents
        return privileges

    @staticmethod
    def isImpersonationToken(hToken, loggingOnError=True):
        '''
        Return True if token is Impersonation Token, or False.

        Impersonation: The server can impersonate the client's security context when communicating with services on
        remote systems.
        :param hToken: A handle to access token
        :param loggingOnError: print error message on debug oputput if disable.
        :return: Return True if an impersonation Token. Otherwise False.
        '''
        level = TokenManager.getTokenInformationTokenImpersonationLevel(hToken, loggingOnError=loggingOnError)
        if level == None:
            return False
        elif level == SecurityImpersonation:
            return True
        else:
            return False

    @staticmethod
    def isDelegationToken(hToken, loggingOnError=True):
        '''
        Return True if token is Delegation Token, or False.

        Delegation: The server can impersonate the client's security context when communicating with services on
        remote systems.
        :param hToken: A handle to access token
        :param loggingOnError: print error message on debug oputput if disable.
        :return: Return True if an Delegation Token. Otherwise False.
        '''
        level = TokenManager.getTokenInformationTokenImpersonationLevel(hToken, loggingOnError=loggingOnError)
        if level == None:
            return False
        elif level == SecurityDelegation:
            return True
        else:
            return False

    @staticmethod
    def isIdentificationToken(hToken, loggingOnError=True):
        '''
        Return True if token is Identification Token, or False.

        Identification: The server can obtain information such as security identifiers and privileges, but the server
        cannot impersonate the client.
        :param hToken: A handle to access token
        :param loggingOnError: print error message on debug oputput if disable.
        :return: Return True if an Identification Token. Otherwise False.
        '''
        level = TokenManager.getTokenInformationTokenImpersonationLevel(hToken, loggingOnError=loggingOnError)
        if level == None:
            return False
        elif level == SecurityIdentification:
            return True
        else:
            return False

    @staticmethod
    def isAnonymousToken(hToken, loggingOnError=True):
        '''
        Return True if token is Anonymous Token, or False.

        Anonymous: The server cannot obtain information about the client and cannot impersonate the client.
        :param hToken: A handle to access token
        :param loggingOnError: print error message on debug oputput if disable.
        :return: Return True if an Anonymous Token. Otherwise False.
        '''
        level = TokenManager.getTokenInformationTokenImpersonationLevel(hToken, loggingOnError=loggingOnError)
        if level == None:
            return False
        elif level == SecurityAnonymous:
            return True
        else:
            return False

    @staticmethod
    def getTokenIntegrityLevel(hToken):
        '''
        Get integrity level from token as a int (DWORD)

        :param hToken: A handle to access token
        :return: None if an error or integrity level as int
        '''
        integrityLvlInfo = TokenManager.getTokenInformationTokenIntegrityLevel(hToken)
        if integrityLvlInfo == None:
            return None
        sidString = TokenManager.convertSidToStringSid(integrityLvlInfo.Label.Sid)
        logging.debug("SID: {0}".format(sidString))
        pSidSize = GetSidSubAuthorityCount(integrityLvlInfo.Label.Sid)
        # 'If the function fails, the return value is undefined'
        res = GetSidSubAuthority(integrityLvlInfo.Label.Sid, pSidSize.contents.value - 1)
        level = res.contents.value
        logging.debug("Integrity level Value from handle: {0}".format(level))
        return level

    @staticmethod
    def getTokenIntegrityLevelAsString(hToken):
        '''
        Get integrity level from token as a String.

        :param hToken: A handle to access token
        :return: None if an error. Otherwise: String  'Untrusted', 'Low', 'Medium', 'Medium high', 'High',
        'System', 'Protected process'
        '''
        level = TokenManager.getTokenIntegrityLevel(hToken)
        intLvlString = MAPPING_INTEGRITY_LEVEL.get(level)
        logging.debug("Integrity Level from handle: {0} ({1})".format(intLvlString, level))
        return intLvlString

    @staticmethod
    def getTokenInformationTokenGroups(hToken):
        '''
        Get information about the group security identifiers (SIDs) in an access token.

        :param hToken: A handle to access token
        :return: a list of group SID (structure, not strings), empty list or None (if an error)
        '''
        # Call with zero length to determine what size buffer
        allGroups = []
        returnLength = DWORD()
        res = GetTokenInformation(hToken,
                                  TokenGroups,
                                  None,
                                  0,
                                  returnLength)
        if returnLength == 0:
            logging.error("Impossible to get size before getting Token Groups: {0}".format(GetLastError()))
            return None
        # Get data
        buffer = create_string_buffer(returnLength.value)
        res = GetTokenInformation(hToken,
                                  TokenGroups,
                                  byref(buffer),
                                  returnLength.value,
                                  returnLength)
        if returnLength == 0:
            logging.error("Impossible to get Token Groups: {0}".format(e))
            return None
        groupsCount = cast(buffer, POINTER(ULONG))[0]
        groups = cast(buffer, POINTER(tokenGroups(groupsCount)))[0]
        for i in range(groups.GroupCount):
            aGroup = groups.Groups[i]
            allGroups.append(aGroup)
        return allGroups

    @staticmethod
    def getTokenInformationTokenSessionId(hToken):
        '''
        Get the Terminal Services session identifier that is associated with the token.

        If the token is associated with the terminal server client session, the session identifier is nonzero.
        Windows Server 2003 and Windows XP:  If the token is associated with the terminal server console session,
        the session identifier is zero.
        In a non-Terminal Services environment, the session identifier is zero.
        https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
        :param hToken: A handle to access token
        :return: None if an error, otherwise id (int)
        '''
        returnLength = DWORD()
        res = GetTokenInformation(hToken,
                                  TokenSessionId,
                                  None,
                                  0,
                                  returnLength)
        if returnLength == 0:
            logging.error("Impossible to get size before getting TokenSession Id: {0}".format(GetLastError()))
            return None
        # Get data
        buffer = create_string_buffer(returnLength.value)
        res = GetTokenInformation(hToken,
                                  TokenSessionId,
                                  byref(buffer),
                                  returnLength.value,
                                  returnLength)
        if returnLength == 0:
            logging.error("Impossible to get TokenSession Id: {0}".format(e))
            return None
        id = cast(buffer, POINTER(DWORD)).contents.value
        return id

    @staticmethod
    def getTokenInformationTokenLogonSid(hToken):
        '''
        Get the token's logon SID.
        Valid starting with Windows Vista.
        TODO: does not seems to work. Always error 1168 ?
        :param hToken: A handle to access token
        :return: None if an error or TOKEN_GROUPS structure
        '''
        infoSize = DWORD(0)
        status = GetTokenInformation(hToken,
                                     TokenLogonSid,
                                     c_void_p(),
                                     0,
                                     byref(infoSize))
        if status == 0 or infoSize.value == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_INSUFFICIENT_BUFFER:
                pass
            if errorMessage.winerror == ERROR_NOT_FOUND:
                logging.debug("Impossible to get size for getTokenLogonSid: {0}".format(errorMessage))
                return None
            else:
                logging.debug("Impossible to get size for getTokenLogonSid: {0}".format(errorMessage))
                return None
        buffer = create_string_buffer(infoSize.value)
        #resize(tokenInfo, infoSize.value)
        status = GetTokenInformation(hToken,
                                     TokenLogonSid,
                                     byref(buffer),
                                     infoSize,
                                     byref(infoSize))
        if status == 0:
            logging.debug("Impossible to get getTokenLogonSid: {0}".format(getLastErrorMessage()))
            return None
        groupsCount = cast(buffer, POINTER(ULONG))[0]
        groups = cast(buffer, POINTER(tokenGroups(groupsCount)))[0]
        return groups

    @staticmethod
    def getAllUserRightsForEffectiveToken():
        """
        Get all User Rights (privileges) associated with the current thread (thread token or process token).

        :return: a dict {'userRightname':statusID} or None if an error.
        """
        hToken = TokenManager.getCurrentThreadEffectiveToken()
        if hToken == None:
            return None
        privs = TokenManager.getAllUserRights(hToken)
        TokenManager.closeHandle(hToken)
        return privs

    @staticmethod
    def printAllEffectiveUserRights(printOnDebug=False):
        """
        Print all User Rights (privileges) associated with the current thread (thread token or process token)

        :param printOnDebug: print error on stdout if error and not stderr.
        :return: None if an error or True
        """
        info = TokenManager.getAllUserRightsForEffectiveToken()
        if info == None:
            logging.error("Impossible to print all User Rights (privileges) associated with the current thread")
            return None
        m = "Privileges (User Rights) for current thread:"
        if printOnDebug == True: logging.debug(m)
        else: print(m)
        for aPriv in info:
            if info[aPriv] & SE_PRIVILEGE_ENABLED:
                m= "- {0}: Enabled".format(aPriv)
                if printOnDebug == True: logging.debug(m)
                else: print(m)
            elif info[aPriv] & SE_PRIVILEGE_ENABLED_BY_DEFAULT:
                m = "- {0}: Enabled by default".format(aPriv)
                if printOnDebug == True: logging.debug(m)
                else: print(m)
            else:
                m= "- {0}: Disabled".format(aPriv)
                if printOnDebug == True: logging.debug(m)
                else: print(m)
        return True

    @staticmethod
    def getAllUserRights(hToken):
        """
        Get all User Rights (privileges) associated the primary or impersonation token of your choice.

        User right can be enabled or not.
        Notice: Appply a mask (e.g. SE_PRIVILEGE_ENABLED) on statusID for getting status
        :param hToken: handle to a token
        :return: a dict {'userRightname':statusID} or None if an error.
        """
        privDict = {}
        if hToken == None:
            logging.error("Impossible to Get all User Rights, hToken is set to None")
            return None
        privileges = TokenManager.getTokenInformationTokenPrivileges(hToken)
        if privileges == None:
            logging.error("Impossible to Get all User Rights")
            return None
        logging.debug("Number of privileges: {0}".format(privileges.PrivilegeCount))
        for aPriv in privileges:
            privName = aPriv.getName()
            privDict[privName] = aPriv.Attributes
        return privDict

    @staticmethod
    def getAllUserRightsForPrimaryToken():
        """
        Get all User Rights (privileges) associated with the current process token (primary token).

        Important notice: use current process token by default. If thread is impersonating, getAllUserRightsForEffectiveToken()
        should be used.
        User right can be enabled or not.
        Notice: Appply a mask (e.g. SE_PRIVILEGE_ENABLED) on statusID for getting status
        :return: a dict {'userRightname':statusID} or None if an error.
        """
        hToken = TokenManager.getCurrentProcessToken()
        if hToken == None:
            return None
        privs = TokenManager.getAllUserRights(hToken)
        TokenManager.closeHandle(hToken)
        return privs

    @staticmethod
    def getUserRightStatus(hToken, userRightName):
        """
        Return the status of the user right for given primary or impersonation token.

        Return None if the token has not this right.
        Be carefull, case sensitive ('SeDebugPrivilege' and not 'sedebugprivilege')
        :param hToken: handle to token
        :param userRightName: privilege name (e.g. "SeDebugPrivilege")
        :return: return int status or None if an error.
        """
        userRightsDict = TokenManager.getAllUserRights(hToken)
        if userRightsDict == None:
            return None
        if userRightName in userRightsDict:
            return userRightsDict[userRightName]
        else:
            return None

    @staticmethod
    def getUserRightStatusForPrimaryToken(userRightName):
        """
        Return the status of the user right for current process token (primary token only).

        Return None if the current process has not this right.
        Be carefull, case sensitive ('SeDebugPrivilege' and not 'sedebugprivilege')
        :param userRightName: privilege name (e.g. "SeDebugPrivilege")
        :return: return int status or None if an error.
        """
        userRightsDict = TokenManager.getAllUserRightsForPrimaryToken()
        if userRightsDict == None:
            return None
        if userRightName in userRightsDict:
            return userRightsDict[userRightName]
        else:
            return None

    @staticmethod
    def getUserRightStatusForEffectiveToken(userRightName):
        """
        Return the status of the user right for current effective token (impersonation token or primary token).

        Return None if the current process has not this right.
        Be carefull, case sensitive ('SeDebugPrivilege' and not 'sedebugprivilege')
        :param userRightName: privilege name (e.g. "SeDebugPrivilege")
        :return: return int status or None if an error.
        """
        userRightsDict = TokenManager.getAllUserRightsForEffectiveToken()
        if userRightsDict == None:
            return None
        if userRightName in userRightsDict:
            return userRightsDict[userRightName]
        else:
            return None

    @staticmethod
    def getUserRightsEnabledForPrimaryToken():
        """
        Get all privileges (User Rights) which are enabled for the current process token.

        Notice: if thread is impersonating, get process token, not impersonation token.
        See PRIVILEGE_BITS and PRIVILEGE_BITS_INV for list of privileges
        :return: Return None if an error or a list of all privilege names (e.g. ['SeDebugPrivilege', etc])
        """
        userRightsEnabled = []
        userRightsDict = TokenManager.getAllUserRightsForPrimaryToken()
        if userRightsDict == None:
            return None
        for aUserRightName in userRightsDict:
            if bool(userRightsDict[aUserRightName] & SE_PRIVILEGE_ENABLED) == True:
                userRightsEnabled.append(aUserRightName)
        logging.debug("User Rights enabled for current process: {0}".format(userRightsEnabled))
        return userRightsEnabled

    @staticmethod
    def getUserRightsEnabledForEffectiveToken():
        """
        Get all privileges (User Rights) which are enabled for the current effective token
        (impersonation or primary token).

        See PRIVILEGE_BITS and PRIVILEGE_BITS_INV for list of privileges
        :return: Return None if an error or a list of all privilege names (e.g. ['SeDebugPrivilege', etc])
        """
        userRightsEnabled = []
        userRightsDict = TokenManager.getAllUserRightsForEffectiveToken()
        if userRightsDict == None:
            return None
        for aUserRightName in userRightsDict:
            if bool(userRightsDict[aUserRightName] & SE_PRIVILEGE_ENABLED) == True:
                userRightsEnabled.append(aUserRightName)
        logging.debug("User Rights enabled for current process: {0}".format(userRightsEnabled))
        return userRightsEnabled

    @staticmethod
    def enableUserRight(privilegeStr, hToken=None):
        """
        Enable Privilege on token, if no token is given the function gets the token of the current thread token
        (impersonation token or primary token if no impersonation). A token can be chosen otherwise.

        This function cannot add new privileges to the access token. It can only enable or disable the token's
        existing privileges.
        :param privilegeStr: privilege name. Example: SeDebugPrivilege. Important notice: case sensitive.
        :param hToken: handle to token or None for effective token for current thread
        :return: Return False if an error, otherwise return true
        """
        if hToken == None:
            logging.debug("Trying to enable the User Right {0} on effective token...".format(repr(privilegeStr)))
            allUserRights = TokenManager.getAllUserRightsForEffectiveToken()
        else:
            logging.debug("Trying to enable the User Right {0} on chosen token...".format(repr(privilegeStr)))
            allUserRights = self.getAllUserRights(hToken)
        if allUserRights == None:
            return False
        if privilegeStr not in allUserRights:
            logging.info("Current token has not the right {0}, impossible to enable it".format(repr(privilegeStr)))
            return False
        if bool(allUserRights[privilegeStr] & SE_PRIVILEGE_ENABLED) == True:
            logging.debug("User Right {0} is already enabled on token, nothing to do".format(privilegeStr))
            return True
        if hToken == None:
            dAcess = (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
            theTokenToMod = TokenManager.getCurrentThreadEffectiveToken(desiredAccessThread=dAcess,
                                                                        desiredAccessProcess=dAcess)
        else:
            theTokenToMod = hToken
        status = TokenManager.adjustTokenPrivileges(theTokenToMod, privilegeStr, state=SE_PRIVILEGE_ENABLED)
        if hToken == None:
            TokenManager.closeHandle(theTokenToMod)
        return status

    @staticmethod
    def disableAllUserRights(hToken=None):
        '''
        Disables all of the token's privileges.

        Use current effective token by default, Impersonation token or primary token if thread is not impersonating.
        :param hToken: handle to token. If none, use current effective token for thread.
        :return: True or False if an error
        '''
        if hToken == None:
            logging.debug("Trying to disable all User Rights on effective token...")
            allUserRights = TokenManager.getAllUserRightsForEffectiveToken()
            dAcess = (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
            theTokenToMod = TokenManager.getCurrentThreadEffectiveToken(desiredAccessThread=dAcess,
                                                                        desiredAccessProcess=dAcess)
        else:
            logging.debug("Trying to disable all User Rights on chosen token...")
            allUserRights = self.getAllUserRights(hToken)
            theTokenToMod = hToken
        for aPrivName in allUserRights:
            if bool(allUserRights[aPrivName] & SE_PRIVILEGE_ENABLED) == True:
                status = TokenManager.adjustTokenPrivileges(theTokenToMod, aPrivName, state=SE_PRIVILEGE_REMOVED)
        if hToken == None:
            TokenManager.closeHandle(theTokenToMod)
        return True

    @staticmethod
    def enableAllUserRights(hToken=None):
        '''
        Enables all of the token's privileges.

        Use current effective token by default, Impersonation toen or primary token if thread is not impersonating.
        :param hToken: handle to token. If none, use current effective token for thread.
        :return: True or False if an error
        '''
        if hToken == None:
            logging.debug("Trying to enable all User Rights on effective token...")
            allUserRights = TokenManager.getAllUserRightsForEffectiveToken()
            dAcess = (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
            theTokenToMod = TokenManager.getCurrentThreadEffectiveToken(desiredAccessThread=dAcess,
                                                                        desiredAccessProcess=dAcess)
        else:
            logging.debug("Trying to enable all User Rights on chosen token...")
            allUserRights = self.getAllUserRights(hToken)
            theTokenToMod = hToken
        if allUserRights == None:
            logging.error("Impossible to get all user rights for current effective thread")
            return False
        for aPrivName in allUserRights:
            if bool(allUserRights[aPrivName] & SE_PRIVILEGE_ENABLED) == False:
                status = TokenManager.adjustTokenPrivileges(theTokenToMod, aPrivName, state=SE_PRIVILEGE_ENABLED)
        if hToken == None:
            TokenManager.closeHandle(theTokenToMod)
        return True

    @staticmethod
    def lookupPrivilegeValue(privilegeStr):
        '''
        Retrieves the locally unique identifier (LUID) used on the system to locally represent the specified
        privilege name.
        :param privilegeStr: privilege name. Important notice: case sensitive.
        :return: LUID
        '''
        privilegeName = str(privilegeStr)
        privilegeId = LUID()
        try:
            LookupPrivilegeValue(None, privilegeName, byref(privilegeId))
        except Exception as e:
            logging.error("Impossible to LookupPrivilegeValue for {0}: {1}".format(str(privilegeName), e))
            return None
        return privilegeId

    @staticmethod
    def adjustTokenPrivileges(hToken, privilegeStr, state=SE_PRIVILEGE_ENABLED):
        '''
        Enables or disables privileges in the specified access token.

        Important: Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
        :param hToken: handle to token to modify
        :param privilegeStr: privilege name. Example: SeDebugPrivilege. Important notice: case sensitive.
        :param state: SE_PRIVILEGE_ENABLED or SE_PRIVILEGE_REMOVED
        :return: True or False if an error
        '''
        privilegeName = str(privilegeStr)
        privilegeId = TokenManager.lookupPrivilegeValue(privilegeStr)
        if privilegeId == None:
            return False
        newPriv = TOKEN_PRIVILEGES()
        newPriv.PrivilegeCount = 1
        newPriv.Privileges[0].Luid = privilegeId
        newPriv.Privileges[0].Attributes = state
        try:
            AdjustTokenPrivileges(hToken, False, byref(newPriv), sizeof(newPriv), None, None)
        except Exception as e:
            logging.error("Impossible to AdjustTokenPrivileges for {0}: {1}".format(str(privilegeName), e))
            return False
        logging.debug("Privilege {0} is {1} now on token".format(repr(privilegeStr), state))
        return True


    @staticmethod
    def isRestrictedToken(hToken):
        '''
        Returns True if token contains a list of restricted security identifiers (SIDs).

        If the token contains a list of restricting SIDs, the return value is True.
        If the token does not contain a list of restricting SIDs, the return value is False.
        Remark: The CreateRestrictedToken function can restrict a token by disabling SIDs, deleting privileges,
        and specifying a list of restricting SIDs. The IsTokenRestricted function checks only for the list of
        restricting SIDs. If a token does not have any restricting SIDs, IsTokenRestricted returns FALSE, even
        though the token was created by a call to CreateRestrictedToken.
        :param hToken: A handle to access token
        :return: None, True or False
        '''
        status= IsTokenRestricted(hToken)
        if status == 0:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_SUCCESS:
                return False
            else:
                logging.error("Impossible to get restricted token status: {0}".format(errorMessage))
                return None
        else:
            return True

    @staticmethod
    def canImpersonateToken(hToken, loggingOnError=False):
        """
        Check if the given token can be used for impersonation.

        Use ImpersonateLoggedOnUser() and after RevertToSelf()
        :param loggingOnError: print error on stderr if enabled
        :return: True if can be impersonated, otherwise False
        """
        try:
            # Important notice: one of the following has to be true:
            # - The requested impersonation level of the token is less than
            # SecurityImpersonation, such as SecurityIdentification or SecurityAnonymous.
            # - The caller has the SeImpersonatePrivilege privilege.
            # - A process (or another process in the caller's logon session) created the
            # token using explicit credentials through LogonUser or LsaLogonUser function.
            # - The authenticated identity is same as the caller.
            ImpersonateLoggedOnUser(hToken)
        except Exception as e:
            m = "Impossible to impersonate handle: {0}".format(e)
            if loggingOnError==False:
                logging.error(m)
            else:
                logging.debug(m)
            return False
        else:
            try:
                RevertToSelf()
            except Exception as e:
                logging.critical("Impossible to terminate the impersonation: {0}".format(e))
            logging.debug("Impersonation of token {0}: successful".format(hToken))
            return True

    @staticmethod
    def getPrimaryTokenOfPid(pid, impersonation=True, loggingOnError=False, full=True):
        '''
        Get the primary token of a pid and return details in a dict

        :param pid: process id.
        :param impersonation: Try to impersonate the token if possible and save info in dict
        :param loggingOnError: print error message on debug output if disable. Stderr output if enable.
        :param full: if enabled, get all information about tokens, othwerwise limited information
        :return: None or dictionary. See extractTokenInfo() for all parameters.
        '''
        tokenDetails = None
        logging.debug("Getting primary token of pid {0}...".format(pid))
        pToken = TokenManager.getProcessTokenOfPid(pid,
                                                tokenAcess=MAXIMUM_ALLOWED,
                                                loggingOnError=loggingOnError)
        if pToken == None:
            return None
        else:
            canImpersonate = None
            #canImpersonateViaImpersonation = None
            if impersonation == True:
                canImpersonate = False
                # TOKEN_QUERY and TOKEN_DUPLICATE are required for ImpersonateLoggedOnUser() when primary token
                hPrimaryToken = TokenManager.getProcessTokenOfPid(pid,
                                                        tokenAcess=TOKEN_QUERY | TOKEN_DUPLICATE,
                                                        loggingOnError=loggingOnError)
                if hPrimaryToken != None:
                    canImpersonate = TokenManager.canImpersonateToken(hPrimaryToken, loggingOnError=loggingOnError)
                    if canImpersonate == True:
                        logging.debug("We can impersonate primary token of pid {0}".format(pid))
                    else:
                        logging.debug("We can NOT impersonate primary token of pid {0}".format(pid))
                    TokenManager.closeHandle(hPrimaryToken)
            else:
                pass
            tokenDetails = TokenManager.extractTokenInfo(pToken, handleValue=None, handleID=None, full=full)
            tokenDetails['canimpersonate'] = canImpersonate
            #IMPORTANT NOTICE: Don't close pToken handle because is saved in tokenDetails
        logging.debug("Primary token of pid {0} got".format(pid))
        return tokenDetails

    @staticmethod
    def getImpersonationTokenFromPrimaryTokenForPID(pid, desiredAccess=TOKEN_ALL_ACCESS, loggingOnError=True):
        '''
        Get primary token of pid and returns impersonation token with duplicateToken().

        Return a new access token that has been duplicated from the primary token of the pid.
        :param pid: pid of the targted process
        :param loggingOnError: print error message on debug output if disable. Otherwise stderr. Used for getting
                               process token only.
        :param desiredAccess: Type of access required for the handle, combination of win32security.TOKEN_* flags
                              To request the same access rights as the existing token, specify zero. To request all
                              access rights that are valid for the caller, specify MAXIMUM_ALLOWED.
        :return: The impersonation token or None if an error
        '''
        hTokendupe = None
        #TOKEN_DUPLICATE is required on token wor duplication
        hToken = TokenManager.getProcessTokenOfPid(pid, tokenAcess=TOKEN_DUPLICATE, loggingOnError=loggingOnError)
        if hToken == None:
            return None
        hTokendupe = TokenManager.duplicateToken(hToken,
                                         impersonationLevel=SecurityImpersonation,
                                         desiredAccess=desiredAccess,
                                         tokenType=TokenPrimary)
        if hTokendupe == None:
            logging.error("Impossible to Duplicate Token from primary token of pid {0}".format(pid))
            TokenManager.closeHandle(hToken)
            return None
        TokenManager.closeHandle(hToken)
        return hTokendupe

    @staticmethod
    def getImpersonationTokenFromPrimaryTokenForCurrentProcess(desiredAccess=TOKEN_ALL_ACCESS):
        '''
        Get primary token of current process and returns impersonation token with duplicateToken().

        Return a new access token that has been duplicated from the primary token of current process.
        :param desiredAccess: Type of access required for the handle, combination of win32security.TOKEN_* flags
                              To request the same access rights as the existing token, specify zero. To request all
                              access rights that are valid for the caller, specify MAXIMUM_ALLOWED.
        :return: The impersonation token or None if an error
        '''
        hTokendupe = None
        hToken = TokenManager.getCurrentProcessToken()
        if hToken == None:
            return None
        hTokendupe = TokenManager.duplicateToken(hToken,
                                                 impersonationLevel=SecurityImpersonation,
                                                 desiredAccess=desiredAccess,
                                                 tokenType=TokenPrimary)
        if hTokendupe == None:
            logging.error("Impossible to Duplicate Token from primary token for current process".format(pid))
            TokenManager.closeHandle(hToken)
            return None
        TokenManager.closeHandle(hToken)
        return hTokendupe

    @staticmethod
    def isEffectiveTokenInBuiltinAdministrators():
        """
        Check if effective token is in built in administrators groups.

        By default, check the impersonation token if thread is impersonating or primary token.
        See checkTokenMembership() for more details.
        :param hToken: A handle to an access token. If present, this token is checked for the SID. If not present,
                       then the current effective token is used. This must be an impersonation token.
        :return: True if token in administrators group.Otherwise False or None if an error
        """
        SECURITY_MAX_SID_SIZE = 68
        sid = create_string_buffer(SECURITY_MAX_SID_SIZE)
        size = DWORD(SECURITY_MAX_SID_SIZE)
        try:
            CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinBuiltinAdministratorsSid, None, byref(sid), byref(size))
        except Exception as e:
            logging.error("Impossible to get the Builtin Administrators Sid: {0}".format(e))
            return None
        return TokenManager.checkTokenMembership(sid, None)

    @staticmethod
    def isTokenInBuiltinAdministrators(hToken):
        """
        Check if given token is in built in administrators groups.

        :param hToken: A handle to an access token. If present, this token is checked for the SID. If not present,
                       then the current effective token is used. This must be an impersonation token.
        :return: True if token in administrators group.Otherwise False or None if an error
        """
        SECURITY_MAX_SID_SIZE = 68
        sid = create_string_buffer(SECURITY_MAX_SID_SIZE)
        size = DWORD(SECURITY_MAX_SID_SIZE)
        try:
            CreateWellKnownSid(WELL_KNOWN_SID_TYPE.WinBuiltinAdministratorsSid, None, byref(sid), byref(size))
        except Exception as e:
            logging.error("Impossible to get the Builtin Administrators Sid: {0}".format(e))
            return None
        return TokenManager.checkTokenMembership(sid, hToken)

    @staticmethod
    def checkTokenMembership(sid, hToken=None):
        '''
        Determines whether a specified security identifier (SID) is enabled.

        By default, use the effective token i.e. impersonation token or primary token if thread is not
        impersonating. Otherwise, use the given token.
        Use checktokenmembershipEx() when possible (win8.1 and superior) or checktokenmembership()
        To determine group membership for app container tokens, checktokenmembershipEx is used.
        :param sid: sid structure
        :param hToken: A handle to an access token. If present, this token is checked for the SID. If not present,
                       then the current effective token is used. This must be an impersonation token.
        :return: True or False. None if an error.
        '''
        if CHECK_TOKEN_MEMBERSHIP_EX_AVAILABLE == True:
            CTMF_INCLUDE_APPCONTAINER = 0x00000001
            isMember = BOOL()
            try:
                #On win8.1 or hiher only
                status = CheckTokenMembershipEx(hToken, sid, CTMF_INCLUDE_APPCONTAINER, byref(isMember))
            except Exception as e:
                logging.error("Impossible to CheckTokenMembershipEx(): {0}".format(e))
                help(e)
                return None
            if isMember.value == True:
                return True
            else:
                return False
        else:
            isMember = BOOL()
            try:
                CheckTokenMembership(hToken, byref(sid), byref(isMember))
            except Exception as e:
                logging.error("Impossible to CheckTokenMembership(): {0}".format(e))
                return None
            if isMember.value == True:
                return True
            else:
                return False

    @staticmethod
    def getCurrentThreadToken(desiredAccess=TOKEN_QUERY):
        """
        Get current thread token.

        Use OpenThreadToken() on the current thread token (GetCurrentThread()).
        If the thread has not an impersonation token, returns None.
        :param desiredAccess: access mask that specifies the requested types of access to the access token.
        :return: hToken or None if an error or thread is not impersonating
        """
        logging.debug("Getting current thread token")
        openAsSelf = False
        hToken = HANDLE(c_void_p(-1).value)
        #Retrieves a pseudo handle for the calling thread.
        hThread = GetCurrentThread()
        #hThread does NOT need to be CLOSED when it is no longer needed
        try:
            #OpenAsSelf=FALSE because the access check is to be made against the current security context of the thread
            #calling the OpenThreadToken function.
            OpenThreadToken(hThread, desiredAccess, False, byref(hToken))
        except Exception as e:
            logging.error("Impossible to OpenThreadToken 1: {0}".format(e))
            return None
        if hToken.value == None:
            errorMessage = getLastErrorMessage()
            if errorMessage.winerror == ERROR_NO_TOKEN:
                logging.debug("Current thread is not impersonating. Consequently, NO impersonation token for current thread ")
            else:
                logging.error("Impossible to OpenThreadToken 2: {0}".format(getLastErrorMessage()))
            return None
        return hToken

    @staticmethod
    def getCurrentThreadEffectiveToken(desiredAccessThread=TOKEN_QUERY, desiredAccessProcess=TOKEN_QUERY):
        '''
        Retrieves a handle to the token that is currently in effect for
        the thread, which is the thread token if one exists and the process token otherwise.

        Not tested: Duplicate by the DuplicateHandle function or the DuplicateToken function.
        https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadeffectivetoken
        :param desiredAccessThread: access mask for thread token
        :param desiredAccessProcess:  access mask for process token
        :return: handle to thread token or process token or None if an error
        '''
        threadToken = TokenManager.getCurrentThreadToken(desiredAccess=desiredAccessThread)
        if threadToken == None:
            pToken = TokenManager.getCurrentProcessToken(desiredAccess=desiredAccessProcess)
            return pToken
        else:
            return threadToken

    @staticmethod
    def printCurrentPrimaryToken(printFull=True, printLinked=True):
        '''
        Print the primary token of this current process

        :param printFull: Print all information about each token.
        :param printLinked: Print the linked token if possible.
        :return: True or None (if an error or thread is not impersonating)
        '''
        print("Current primary token:")
        logging.debug("Printing current primary token on stdout")
        hToken = TokenManager.getCurrentProcessToken()
        if hToken == None:
            print("Impossible to get primary token for current process")
            return None
        tokenDetails = TokenManager.extractTokenInfo(hToken)
        TokenManager.printTokens({-1: [tokenDetails]}, printFull=printFull, printLinked=printLinked)
        TokenManager.closeHandle(hToken)
        return True

    @staticmethod
    def printCurrentThreadToken(printFull=True, printLinked=True):
        '''
        Print the token that is currently in effect for the thread (primary or impersonation), which is the thread token.

        :param printFull: Print all information about each token.
        :param printLinked: Print the linked token if possible.
        :return: True or None (if an error or thread is not impersonating)
        '''
        print("Current Thread token:")
        logging.debug("Printing current thread token on stdout")
        hToken = TokenManager.getCurrentThreadToken()
        if hToken == None:
            print("Current Thread is not impersonating. Consequently, no impersonation token for current thread")
            return None
        tokenDetails = TokenManager.extractTokenInfo(hToken)
        TokenManager.printTokens({-1:[tokenDetails]}, printFull=printFull, printLinked=printLinked)
        TokenManager.closeHandle(hToken)
        return True

    @staticmethod
    def printCurrentThreadEffectiveToken(printFull=True, printLinked=True):
        '''
        Print the token that is currently in effect for the thread, which is the thread token if one exists and the
        process token otherwise.

        :param printFull: Print all information about the token.
        :param printLinked: Print the linked token if possible.
        :return: True or None if an error
        '''
        print("Current Thread token:")
        logging.debug("Printing current thread token on stdout")
        hToken = TokenManager.getCurrentThreadEffectiveToken()
        if hToken == None:
            return None
        TokenManager.printTokenFromHandle(hToken, printFull=printFull, printLinked=printLinked)
        TokenManager.closeHandle(hToken)
        return True

    @staticmethod
    def printTokenFromHandle(hToken, printFull=True, printLinked=True):
        '''
        Print the token hToken

        :param hToken: A handle to an access token
        :param printFull: Print all information about the token.
        :param printLinked: Print the linked token if possible.
        :return: True or None if an error
        '''
        tokenDetails = TokenManager.extractTokenInfo(hToken)
        TokenManager.printTokens({-1: [tokenDetails]}, printFull=printFull, printLinked=printLinked)

    @staticmethod
    def extractTokenInfo(pToken, handleValue=None, handleID=None, full=True):
        """
        Extract a maximum of information from a token.

        :param pToken: a handle to an access token
        :param handleValue: value will be saved in returned dictionary.
        :param handleID: value will be saved in returned dictionary.
        :param full: extract all info. If False: only some information
        :return: Empty dictionary if an error of a dictionary with many parameters. See code for all parameters.
        """
        tokenDetails = {}
        tokenDetails['type'] = TokenManager.getTokenInformationTokenType(pToken)
        if isinstance(pToken, c_void_p) == True:
            #Its a pointer
            tokenDetails['token'] = pToken.value
        else:
            tokenDetails['token'] = pToken
        if tokenDetails['type'] == TokenPrimary:
            tokenDetails['hval'] = None  # Handle value
            tokenDetails['ihandle'] = None  # Handle ID
        else:
            tokenDetails['hval'] = handleValue  # Handle value
            tokenDetails['ihandle'] = handleID  # Handle ID
        tokenDetails['sid'] = TokenManager.getTokenSid(pToken) #String
        tokenDetails['accountname'] = TokenManager.getTokenAccountName(pToken)
        # 'Untrusted', 'Low', 'Medium', 'Medium high', 'High', 'System', 'Protected process'
        tokenDetails['intlvl'] = TokenManager.getTokenIntegrityLevelAsString(pToken)
        if full == True:
            tokenDetails['owner'] = TokenManager.getTokenOwnerSid(pToken) #String
            tokenDetails['groups'] = TokenManager.getTokenInformationTokenGroups(pToken) #a list of group SID (structure, not strings), empty list or None
            tokenDetails['priv'] = TokenManager.getAllUserRights(pToken) #a dict {'userRightname':statusID}
            tokenDetails['issystem'] = TokenManager.isSystemToken(pToken) #bool
            tokenDetails['sessionID'] = TokenManager.getTokenInformationTokenSessionId(pToken)  # int
            tokenDetails['elevationtype'] = TokenManager.getTokenInformationTokenElevationType(pToken)  # TokenElevationTypeDefault, TokenElevationTypeFull, or TokenElevationTypeLimited
            tokenDetails['iselevated'] = TokenManager.getTokenInformationTokenElevation(pToken)  # Boolean
        if tokenDetails['type'] == TokenPrimary:
            # To determine if an Access Token is a “limited” Token with a “full” Linked Token
            # attached, call the “GetTokenInformation” API with the “TokenElevationType”
            # information class and check for the “TokenElevationTypeLimited” value. Then, to
            # retrieve a handle to the “full” Linked Token call “GetTokenInformation” with
            # the “TokenLinkedToken” information class.
            if full==True:
                if tokenDetails['elevationtype'] == TokenElevationTypeLimited:
                    # a Token can include a “Link” to another Token and information about which type
                    # it is (“Elevated” or not). When Administrators log in, their initial process
                    # receives a Primary Token with the same group membership and system Privileges
                    # as a standard user would. This Token also has a link to the “full” Administrator
                    # Access Token and a flag that indicates that the current Token is “limited”.
                    tokenDetails['linkedtoken'] = TokenManager.getTokenInformationTokenLinkedToken(pToken)
                else:
                    tokenDetails['linkedtoken'] = None
        else:
            tokenDetails['linkedtoken'] = None
            tokenDetails['implevel'] = TokenManager.getTokenInformationTokenImpersonationLevel(pToken) #SecurityAnonymous, SecurityIdentification, SecurityImpersonation or SecurityDelegation
        if full == True:
            if tokenDetails['type'] == TokenPrimary:
                tokenDetails['tokensource'] = TokenManager.getTokenSourceName(pToken) #String or None
            else:
                tokenDetails['tokensource'] = None
        if full == True:
            tokenDetails['appcontainertoken'] = TokenManager.isAppContainerToken(pToken)  # just for checking function, boolean
            tokenDetails['appcontainersid'] = TokenManager.getTokenInformationAppContainerSid(pToken) #String
            tokenDetails['appcontainernumber'] = TokenManager.getTokenInformationTokenAppContainerNumber(pToken) #Int or None
            tokenDetails['primarysidgroup'] = TokenManager.getTokenPrimaryGroupSID(pToken) #SID
            tokenDetails['isrestricted'] = TokenManager.isRestrictedToken(pToken) #Boolean
            tokenDetails['hasrestricitions'] = TokenManager.isTokenHasRestrictions(pToken) #Boolean
            tokenDetails['defaultdacl'] = TokenManager.getTokenDefaultDacl(pToken) #list of string
            tokenDetails['logonsid'] = TokenManager.getTokenInformationTokenLogonSid(pToken)
            tokenDetails['mandatorypolicy'] = TokenManager.getTokenInformationTokenMandatoryPolicy(pToken) #int
        return tokenDetails

    def filterTokens(self, allTokens, targetPIDs=None, sid=None, intLevel=None, canImpersonate=True):
        '''
        Returns only selected tokens according to filters specified in parameters

        TODO: close handles when not used anymore
        :param allTokens: all tokens
        :param targetPID: list of pids
        :param sid: selected sid
        :param intLevel: integrity level, int value
        :param canImpersonate: filter for impersonation possible or not
        :return: all tokens which have been selected
        '''
        interestingTokenInfo = {}
        if targetPIDs == None:
            targetPIDs = allTokens.keys()
        for aPID in allTokens:
            if aPID in targetPIDs:
                for aTokenInfo in allTokens[aPID]:
                    okSID = None
                    okIntLevel = None
                    okCanImpersonate = None
                    if sid != None:
                        if aTokenInfo['sid'] == sid:
                            okSID = True
                        else:
                            okSID = False
                    if intLevel != None:
                        if aTokenInfo['intlevel'] == intLevel:
                            okIntLevel = True
                        else:
                            okIntLevel = False
                    if canImpersonate != None:
                        if aTokenInfo['canimpersonate'] == canImpersonate:
                            okCanImpersonate = True
                        else:
                            okCanImpersonate = False
                    if (okSID in [True, None] and okIntLevel in [True, None] and okCanImpersonate in [True, None]):
                        if aPID in interestingTokenInfo:
                            interestingTokenInfo[aPID].append(aTokenInfo)
                        else:
                            interestingTokenInfo[aPID] = [aTokenInfo]
                        logging.debug("A token found according to your criteria (pid {0}): {1}".format(aPID, aTokenInfo))
        return interestingTokenInfo

    @staticmethod
    def printThisToken(allTokens, pid, iHandle=None):
        '''
        Print a specific token of allTokens dictionary

        :param allTokens: See getAllTokensAccessible() for allTokens structure.
        :param pid: slected pid
        :param iHandle: ihandle to token for selected pid. None for primary token.
        :return: Return False if not found or True if no problem and printed
        '''
        if pid not in allTokens:
            return None
        for aToken in allTokens[pid]:
                if aToken['ihandle'] == iHandle:
                    TokenManager.printTokens({pid:[aToken]})
                    return True
        return False

    @staticmethod
    def printTokens(allTokens, printFull=True, printLinked=False, initialTab="  ", tab="  "):
        '''
        Print all tokens stored in allTokens.

        :param allTokens: See getAllTokensAccessible() for allTokens structure.
        :param printFull: Print all information about each token.
        :param printLinked: Print the linked token if possible.
        :param initialTab: internally used. Do not modify.
        :param tab: internally used. Do not modify.
        :return: Always True
        '''
        logging.debug("Printing all tokens in the dict...")
        if allTokens == None or allTokens == {}:
            logging.warning("Nothing to print. Dict is empty")
            return False
        for aPID in allTokens:
            if initialTab == tab:
                print("- PID: {0}".format(aPID))
            for aTokenInfo in allTokens[aPID]:
                if initialTab == tab:
                    print('-'*30)
                print(tab+"- PID: {0}".format(aPID))
                for aKey in aTokenInfo:
                    if aKey == 'type':
                        print(tab + "- {0}: {1} ({2})".format(aKey, TOKEN_TYPE_DICT[aTokenInfo[aKey]], aTokenInfo[aKey]))
                    elif aKey == 'elevationtype':
                        print(tab + "- {0}: {1} ({2})".format(aKey, TOKEN_ELEVATION_TYPE_DICT[aTokenInfo[aKey]], aTokenInfo[aKey]))
                    elif aKey == 'implevel':
                        print(tab + "- {0}: {1} ({2})".format(aKey, SECURITY_IMPERSONATION_LEVEL_DICT[aTokenInfo[aKey]], aTokenInfo[aKey]))
                    elif aKey == 'priv':
                        if printFull==True:
                            print(tab+"- Privileges (User Rights):")
                            for aPriv in aTokenInfo[aKey]:
                                if aTokenInfo[aKey][aPriv] & SE_PRIVILEGE_ENABLED:
                                    print(tab+tab+"- {0}: Enabled".format(aPriv))
                                elif aTokenInfo[aKey][aPriv] & SE_PRIVILEGE_ENABLED_BY_DEFAULT:
                                    print(tab+tab+"- {0}: Enabled by default".format(aPriv))
                                else:
                                    print(tab+tab+"- {0}: Disabled".format(aPriv))
                    elif aKey == 'groups':
                        if printFull==True:
                            print(tab+"- Groups:")
                            for aGroup in aTokenInfo[aKey]:
                                groupSIDstr = TokenManager.convertSidToStringSid(aGroup.Sid)
                                nameInfo = getNameFromSid(aGroup.Sid)
                                flagStrings = []
                                isEnable = bool(aGroup.Attributes & GroupAttributes.SE_GROUP_ENABLED)
                                isEnableByDefault = bool(aGroup.Attributes & GroupAttributes.SE_GROUP_ENABLED_BY_DEFAULT)
                                isIntegrity = bool(aGroup.Attributes & GroupAttributes.SE_GROUP_INTEGRITY)
                                isIntegrityEnable = bool(aGroup.Attributes & GroupAttributes.SE_GROUP_INTEGRITY_ENABLED)
                                isLogonId = bool(aGroup.Attributes & GroupAttributes.SE_GROUP_LOGON_ID)
                                isOwner = bool(aGroup.Attributes & GroupAttributes.SE_GROUP_OWNER)
                                isResource = bool(aGroup.Attributes & GroupAttributes.SE_GROUP_RESOURCE)
                                isUseForDenyOnly =  bool(aGroup.Attributes & GroupAttributes.SE_GROUP_USE_FOR_DENY_ONLY)
                                isMandatory = bool(aGroup.Attributes & GroupAttributes.SE_GROUP_MANDATORY)
                                if isEnable == True:
                                    flagStrings.append("ENABLED")
                                if isEnableByDefault == True:
                                    flagStrings.append("ENABLED_BY_DEFAULT")
                                if isIntegrityEnable == True:
                                    flagStrings.append("INTEGRITY_ENABLED")
                                if isLogonId == True:
                                    flagStrings.append("LOGON_ID")
                                if isOwner == True:
                                    flagStrings.append("OWNER")
                                if isResource == True:
                                    flagStrings.append("RESOURCE")
                                if isUseForDenyOnly == True:
                                    flagStrings.append("USE_FOR_DENY_ONLY")
                                if isMandatory == True:
                                    flagStrings.append("MANDATORY")
                                if isIntegrity == True:
                                    flagStrings.append("INTEGRITY")
                                print(tab+tab+"- {0}: {1} ({2})".format(groupSIDstr, nameInfo, ', '.join(flagStrings)))
                    elif aKey == 'linkedtoken' and printLinked==True:
                        if aTokenInfo[aKey]!=None:
                            print(tab + "- Linked Token:")
                            linkedTokenDetauls = TokenManager.extractTokenInfo(aTokenInfo[aKey])
                            firstTokenLinked = {aPID:[linkedTokenDetauls]}
                            TokenManager.printTokens(allTokens=firstTokenLinked, printFull=printFull, tab=tab*3, printLinked=False)
                        else:
                            print(tab + "- Linked Token: None")
                    elif aKey == 'defaultdacl':
                        if printFull == True:
                            print(tab + "- Default DACL:")
                            for anACE in aTokenInfo[aKey]:
                                print(tab + tab + "- {0}".format(anACE))
                    elif aKey == 'mandatorypolicy':
                        if aTokenInfo[aKey] == None:
                            print(tab + "- Mandatory Policy: {0}".format("N/A"))
                        elif aTokenInfo[aKey] == TOKEN_MANDATORY_POLICY_OFF:
                            print(tab + "- Mandatory Policy: {0}".format("OFF"))
                        elif aTokenInfo[aKey] == TOKEN_MANDATORY_POLICY_NO_WRITE_UP:
                            print(tab + "- Mandatory Policy: {0}".format("NO_WRITE_UP"))
                        elif aTokenInfo[aKey] == TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN:
                            print(tab + "- Mandatory Policy: {0}".format("NEW_PROCESS_MIN"))
                        elif aTokenInfo[aKey] == TOKEN_MANDATORY_POLICY_VALID_MASK:
                            print(tab + "- Mandatory Policy: {0}".format("VALID_MASK"))
                    else:
                        print(tab+"- {0}: {1}".format(aKey, aTokenInfo[aKey]))
        return True

    @staticmethod
    def closeAllHandles(allTokens):
        '''
        Close all handles which are opens in allTokens strucuture.

        :param allTokens: See getAllTokensAccessible() for allTokens structure.
        :return: Always True
        '''
        logging.debug("Closing all handles to tokens...")
        for aPID in allTokens:
            for aTokenInfo in allTokens[aPID]:
                TokenManager.closeHandle(aTokenInfo['token'])
        logging.debug("All handles to tokens are closed")
        return True


    #########################################
    # SET FUNCTIONS
    #########################################
    @staticmethod
    def setTokenGroups(hToken, groups):
        '''
        Enables or disables groups already present in the specified access token.

        Important notice:
            - cannot disable groups with the SE_GROUP_MANDATORY attribute in the TOKEN_GROUPS structure.
              Use CreateRestrictedToken instead.
            - cannot enable a group that has the SE_GROUP_USE_FOR_DENY_ONLY attribute.
        e.g.
        TokenManager.printCurrentThreadEffectiveToken()
        hToken = TokenManager.getCurrentThreadEffectiveToken(desiredAccessThread=TOKEN_ALL_ACCESS,desiredAccessProcess=TOKEN_ALL_ACCESS)
        TokenManager.setTokenGroups(hToken, {'S-1-5-80-521322694-906040134-3864710659-1525148216-3451224162':GroupAttributes.SE_GROUP_USE_FOR_DENY_ONLY})
        TokenManager.printCurrentThreadEffectiveToken()
        :param hToken: A handle to an access token
        :param groups: dictionary : {sid:satus, etc}
        :return: True or False (if an error)
        '''
        logging.debug("Trying to Adjust Token Groups according to {0}".format(groups))
        returnLength = DWORD()
        sids = list(groups.keys())
        if groups ==0:
            logging.warning("'Groups' given to setTokenGroups() is empty. Nothing to do")
            return False
        newStateGroups = tokenGroups(len(groups))()
        newStateGroups.GroupCount = len(groups)
        for i in range(newStateGroups.GroupCount):
            aSIDstr = sids[i]
            attrSid = groups[aSIDstr]
            sidObject = PVOID()
            status = ConvertStringSidToSidA(aSIDstr.encode(), pointer(sidObject))
            newStateGroups.Groups[i].Sid = sidObject
            newStateGroups.Groups[i].Attributes = attrSid
        status = AdjustTokenGroups(hToken,
                                   False, #the groups are set according to the information pointed to by the NewState parameter
                                   byref(newStateGroups),
                                   0, #The size, in bytes, of the buffer pointed to by the PreviousState parameter.
                                   None, #A pointer to a buffer that receives a TOKEN_GROUPS structure containing the previous state of any groups the function modifies.
                                   None #A pointer to a variable that receives the actual number of bytes needed for the buffer pointed to by the PreviousState parameter.
                                   )
        if status == 0:
            logging.error("Impossible AdjustTokenGroups: {0}".format(getLastErrorMessage()))
            return False
        logging.debug("AdjustTokenGroups() status good")
        return True

    @staticmethod
    def setTokenSession(hToken, sessionID):
        '''
        Set the session ID of the access token

        :param hToken: A handle to an access token
        :param sessionID: new session ID for the token
        :return: True or False (if an error)
        '''
        newSessionID = DWORD(sessionID)
        status = SetTokenInformation(hToken, TokenSessionId, byref(newSessionID), sizeof(DWORD))
        if status == 0:
            logging.error("Impossible to set session ID of the token {0} to {1}: {2}".format(hToken,
                                                                                             sessionID,
                                                                                             getLastErrorMessage()))
            return False
        else:
            logging.debug("Session ID of the token {0} has been set to {1}".format(hToken, sessionID))
            return True