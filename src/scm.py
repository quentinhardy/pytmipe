# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import logging
from ctypes import *
from windef import *
from utils import *
from windefsd import *
import time

class serviceControlManager():
    """
    For managing Services with ctypes only
    """
    SECURITY_DESC_DICT_KEY = "securityDescriptor"
    CURRENT_STATE_MAPPING = {SERVICE_CONTINUE_PENDING: 'SERVICE_CONTINUE_PENDING',
                             SERVICE_PAUSE_PENDING: 'SERVICE_PAUSE_PENDING',
                             SERVICE_PAUSED: 'SERVICE_PAUSED',
                             SERVICE_RUNNING: 'SERVICE_RUNNING',
                             SERVICE_START_PENDING: 'SERVICE_START_PENDING',
                             SERVICE_STOP_PENDING: 'SERVICE_STOP_PENDING',
                             SERVICE_STOPPED: 'SERVICE_STOPPED',
                             }

    def __init__(self, target="127.0.0.1"):
        """
        """
        logging.debug("Service Control Manager set to {0}".format(repr(target)))
        self.target = target
        self.scHandle = None

    def __getNameFromSid(self, SID):
        """
        It retrieves the name of the account for this SID and the name of the first domain on which this SID is found.
        Use the target for lookup.
        Return None if an error
        Return dict e.g. {'Name': , 'Domain':, 'Type':}
        """
        d = {}
        try:
            d['Name'], d['Domain'], d['Type'] = LookupAccountSid(self.target, pySID)
        except Exception as e:
            logging.error("Impossible to get Name from SID {0} on {1}: {2}".format(repr(pySID), repr(self.target), e))
            return None
        return d

    def openSCManager(self, dbName="ServicesActive", desiredAccess=SC_MANAGER_ALL_ACCESS):
        """
        Establish a connection to target and init the handle to the service control manager.

        - dbName: The name of the service control manager database.
        - desiredAccess: The access to the service control manager (default; SC_MANAGER_ALL_ACCESS)

        IMPORTNAT NOTICE:
        If the target is the local machine, the current user needs to be a local administrator AND he has to run this
        function from a high intergrity level (aka run as an administrator) if the UAC is enabled. Otherwise, the
        access is refused.
        If the target is a remote machine, the current user has to be a local administrator only.

        More details about accesses: https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
        Returns True or False
        """
        self.scHandle = OpenSCManager(bytes(self.target, encoding="utf-8"), bytes(dbName, encoding="utf-8"), desiredAccess)
        if self.scHandle == None:
            logging.error("Impossible to establish a connection with {0} on {1}. Perhaps a time syncronization problem between remote machine and DC: {2}".format(desiredAccess, repr(self.target),GetLastError()))
            return False
        logging.debug("Connected to the Service Manager of target {0} with access {1}. Handle: {2}".format(repr(self.target), desiredAccess, self.scHandle))
        return True

    def openService(self, serviceName, desiredAccess=SC_MANAGER_ALL_ACCESS):
        """
        Returns a handle to the specified service.
        Return None if an error

        For access rights, see https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
        """
        if self.scHandle == None:
            logging.error("Impossible to open service on {0}. You have to establish a connection before".format(repr(self.target)))
            return None
        spscHandle = OpenService(self.scHandle, bytes(serviceName, encoding="utf-8"), desiredAccess)
        if spscHandle == None:
            logging.error("Impossible to open the service {0} on {1}: {2}".format(repr(serviceName), repr(self.target), getLastErrorMessage()))
            return None
        logging.debug("Service {0} opened on the target {1} with access {2}".format(repr(serviceName), repr(self.target),desiredAccess))
        return spscHandle

    def queryServiceObjectSecurityFromHandle(self, spscHandle, securityInformation=OWNER_SECURITY_INFORMATION):
        """
        Retrieves information from the security descriptor for a service
        Return None if an error. Returns security descriptor if no error
        """
        # first we get the size
        lpSecurityDescriptor = None
        cbBufSize = DWORD(0)
        pcbBytesNeeded = DWORD(0)
        try:
            QueryServiceObjectSecurity(spscHandle, securityInformation, lpSecurityDescriptor, cbBufSize, pcbBytesNeeded)
        except WindowsError as e:
            if e.winerror == ERROR_INSUFFICIENT_BUFFER:
                #Normal error, we get size, we can continue
                pass
            else:
                logging.error("Impossible to retrieve size information from the security descriptor of a service: {0}".format(e))
                return None
        except Exception as e:
            logging.error("Impossible to retrieve size information from the security descriptor of a service: {0}".format(e))
            return None
        #Get the information
        lpSecurityDescriptor = create_string_buffer(pcbBytesNeeded.value)
        cbBufSize = DWORD(pcbBytesNeeded.value)
        pcbBytesNeeded = DWORD(0)
        try:
            QueryServiceObjectSecurity(spscHandle, securityInformation, lpSecurityDescriptor, cbBufSize, pcbBytesNeeded)
        except Exception as e:
            logging.error("Impossible to retrieve information from the security descriptor of a service: {0}".format(e))
            return None
        buff = string_at(lpSecurityDescriptor, pcbBytesNeeded.value)
        sd = SECURITY_DESCRIPTOR.from_bytes(buff, SE_OBJECT_TYPE.SE_SERVICE)
        logging.debug("ObjectSecurity from service handle got on target {0}: {1}".format(repr(self.target), str(sd)))
        return sd

    def queryServiceObjectSecurityFromName(self, serviceName, desiredAccess=FILE_ACCESS_MASK.READ_CONTROL, securityInformation=OWNER_SECURITY_INFORMATION):
        """
        Retrieves information from the security descriptor for a service
        Return None if an error. Returns security descriptor if no error
        """
        spscHandle = self.openService(serviceName=serviceName, desiredAccess=desiredAccess)
        if spscHandle == None:
            return None
        details = self.queryServiceObjectSecurityFromHandle(spscHandle, securityInformation)
        if details == None:
            return None
        self.closeThisHandle(spscHandle)
        logging.debug("ObjectSecurity from Service Name {0} got with Service Manager on target {1}".format(repr(serviceName), repr(self.target)))
        return details

    def queryServiceStatusExFromHandle(self, spscHandle):
        """
        Retrieves the current status of the specified service based on the specified information level.
        Return None if an error

        Return for ex:
        {'ServiceType': 32,
         'CurrentState': 2,
         'ControlsAccepted': 0, #The control codes the service accepts and processes in its handler function (see Handler and HandlerEx).
         'Win32ExitCode': 0, #The error code that the service uses to report an error that occurs when it is starting or stopping.
         'ServiceSpecificExitCode': 0, #The service-specific error code that the service returns when an error occurs while the service is starting or stopping.
         'CheckPoint': 0, #The check-point value that the service increments periodically to report its progress during a lengthy start, stop, pause, or continue operation.
         'WaitHint': 2000, #The estimated time required for a pending start, stop, pause, or continue operation, in milliseconds.
         'ProcessId': 1080, #The process identifier of the service.
         'ServiceFlags': 0}
        For details, see https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process
        """
        lpBuffer = SERVICE_STATUS_PROCESS()
        cbBufSize = DWORD(sizeof(SERVICE_STATUS_PROCESS))
        pcbBytesNeeded = DWORD()
        try:
            QueryServiceStatusEx(spscHandle, SC_STATUS_PROCESS_INFO, byref(lpBuffer), cbBufSize, byref(pcbBytesNeeded))
        except Exception as e:
            logging.error("Impossible to get service status of {0} on target {1}: {2}".format(repr(spscHandle), repr(self.target), e))
            return None
        service = ServiceStatusProcess(lpBuffer)
        logging.debug("Service status got: {0}".format(service))
        return service

    def queryServiceConfigFromHandle(self, spscHandle):
        """
        Retrieves the configuration parameters of the specified service.

        Optional configuration parameters are available using the QueryServiceConfig2 function.

        Return None if an error or return dict with all attributes of QUERY_SERVICE_CONFIG strucutre as keys.
        Return for ex:
        {'ServiceType': 16,
         'StartType': 2,
         'ErrorControl': 1,
         'BinaryPathName': 'C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p',
         'LoadOrderGroup': 'AudioGroup',
         'TagId': 0,
         'Dependencies': ['AudioEndpointBuilder', 'RpcSs'],
         'ServiceStartName': 'NT AUTHORITY\\LocalService',
         'DisplayName': 'Windows Audio'
        }
        More details Details here https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configa
        """
        logging.debug("Querying config of a service...")
        configBuffer = create_string_buffer(8192) # maximum size of this array is 8K bytes
        bytesNeeded = DWORD()
        serviceConfig = cast(configBuffer, POINTER(QUERY_SERVICE_CONFIG))
        try:
            QueryServiceConfigW(spscHandle, serviceConfig, 8192, byref(bytesNeeded))
        except Exception as e:
            logging.error("Impossible to get configuration of service from handle on target {0}: {1}".format(repr(self.target), e))
            return None
        conf = serviceConfig.contents.to_dict()
        if conf['BinaryPathName'] == None:
            logging.warning("BinaryPathName of the service is set to None. Probably not enough privileges for querying")
        logging.debug("Service configuration: {0}".format(conf))
        return conf

    def queryServiceConfigFromName(self, serviceName, desiredAccess=SERVICE_CONFIG_DESCRIPTION):
        """
        Retrieves configuration parameters for a service
        Return None if an error or a dict with all attributes of QUERY_SERVICE_CONFIG strucutre as keys.

        Open an handle on service named serviceName, runs queryServiceConfigFromHandle() and close the service handle.

        See queryServiceConfigFromHandle() for more details
        """
        spscHandle = self.openService(serviceName=serviceName, desiredAccess=desiredAccess)
        if spscHandle == None:
            return None
        config = self.queryServiceConfigFromHandle(spscHandle)
        if config == None:
            return None
        self.closeThisHandle(spscHandle)
        return config

    def queryServiceConfig2FromHandle(self, spscHandle, infoLevel=SERVICE_CONFIG_DESCRIPTION):
        """
        Retrieves advanced service configuration options
        Return None if an error
        Type of returned object depends on InfoLevel

        Implemented:
        - SERVICE_CONFIG_DESCRIPTION
        - SERVICE_CONFIG_DELAYED_AUTO_START_INFO
        - SERVICE_CONFIG_FAILURE_ACTIONS_FLAG
        Todo: implemnt other info levels, see https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w
        """
        logging.debug("Retrieving advanced service configuration options...")
        lpBuffer = create_string_buffer(8192)  # maximum size of this array is 8K bytes
        cbBufSize = 8192
        bytesNeeded = DWORD(0)
        try:
            QueryServiceConfig2W(spscHandle, infoLevel, byref(lpBuffer), cbBufSize, byref(bytesNeeded))
        except Exception as e:
            logging.error("Impossible to QueryServiceConfig2 for info Level {0}: {1}".format(infoLevel, e))
            return None
        if infoLevel == SERVICE_CONFIG_DESCRIPTION:
            configBuffer = cast(lpBuffer, POINTER(SERVICE_DESCRIPTION))
            logging.debug("SERVICE_DESCRIPTION: {0}".format(configBuffer.contents.lpDescription))
        elif infoLevel == SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
            configBuffer = cast(lpBuffer, POINTER(SERVICE_DELAYED_AUTO_START_INFO))
            logging.debug("SERVICE_CONFIG_DELAYED_AUTO_START_INFO: {0}".format(bool(configBuffer.contents.fDelayedAutostart)))
        elif infoLevel == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            configBuffer = cast(lpBuffer, POINTER(SERVICE_FAILURE_ACTIONS_FLAG))
            logging.debug("SERVICE_FAILURE_ACTIONS_FLAG: {0}".format(bool(configBuffer.contents.fFailureActionsOnNonCrashFailures)))
        else:
            logging.error("Info Level {0} is NOT implemented in queryServiceConfig2FromHandle()".format(infoLevel))
            return None
        return configBuffer.contents

    def enumServicesStatus(self, serviceType=SERVICE_WIN32, serviceState=SERVICE_STATE_ALL, groupName=None, serviceStartName=None, withConfig=True, withSD=True):
        '''
        Enumerates services in the specified service control manager database.
        The name and status of each service are provided, along with additional data based on the specified
        information level.
        Remark: If the caller does not have the SERVICE_QUERY_STATUS access right to a service, the service is silently
        omitted from the list of services returned to the client.
        If withConfig=False but serviceStartName is defined, enable withConfig.
        :param serviceState: SERVICE_ACTIVE, SERVICE_INACTIVE or SERVICE_STATE_ALL
        :return: None if an error. or if no error: [ {'ServiceName': 'AeLookupSvc',
                                                     'DisplayName': 'Expérience d'application',
                                                     'ServiceType': 32,
                                                     'CurrentState': 1,
                                                     'ControlsAccepted': 0,
                                                     'Win32ExitCode': 0,
                                                     'ServiceSpecificExitCode': 0,
                                                     'CheckPoint': 0,
                                                     'WaitHint': 0,
                                                     'ProcessId':0,
                                                     'ServiceFlags': 0},
                                                     etc]
        '''
        if self.scHandle == None:
            logging.error("Impossible to list service on {0}. You have to establish a connection before".format(repr(self.target)))
            return None
        logging.debug("Getting all services on {0}...".format(repr(self.target)))
        #Define the buffer size that receives the status information
        allServices = []
        infoLevel = SC_ENUM_PROCESS_INFO
        cbBytesNeeded = DWORD(0)
        servicesReturned = DWORD(0)
        resumeHandle = DWORD(0)
        try:
            #The cbBytesNeeded parameter will receive the required size for buffer
            EnumServicesStatusExW(self.scHandle,
                                    infoLevel,
                                    serviceType,
                                    serviceState,
                                    None,
                                    0,
                                    byref(cbBytesNeeded),
                                    byref(servicesReturned),
                                    byref(resumeHandle),
                                    groupName)
        except Exception as e:
            logging.error("Impossible to get number of services with EnumServicesStatusExW() on {0} {0}: {1}".format(repr(self.target), e))
            return None
        logging.debug("Buffer size allocated: {0}".format(cbBytesNeeded.value))
        servicesBuffer = create_string_buffer(cbBytesNeeded.value)
        try:
            success = EnumServicesStatusExW(self.scHandle, infoLevel, serviceType, serviceState, byref(servicesBuffer), sizeof(servicesBuffer), byref(cbBytesNeeded), byref(servicesReturned), byref(resumeHandle), groupName)
        except Exception as e:
            logging.error("Impossible to get services with EnumServicesStatusExW() on {0}: {1}".format(repr(self.target), e))
            return None
        logging.debug("Number of services   : {0}".format(servicesReturned.value))
        if sizeof(servicesBuffer) < (sizeof(ENUM_SERVICE_STATUS_PROCESSW) * servicesReturned.value):
            logging.error("Error with servicesBuffersize ")
        servicesArray = cast(cast(pointer(servicesBuffer), c_void_p), LPENUM_SERVICE_STATUS_PROCESSW)
        for index in range(0, servicesReturned.value):
            aServiceAsDict = {}
            aService = ServiceStatusProcessEntry(servicesArray[index])
            if serviceStartName != None or withConfig==True:
                config = self.queryServiceConfigFromName(serviceName=aService.ServiceName)
                if config != None and (serviceStartName==None or serviceStartName == config['ServiceStartName']):
                    aServiceAsDict = dict(aService.toDict(), **config)
            #logging.debug("A Service {0}/{1}: {2}".format(index, servicesReturned.value, str(aService)))
            if withSD == True:
                securityDescriptor = self.queryServiceObjectSecurityFromName(serviceName=aService.ServiceName)
                aServiceAsDict[self.SECURITY_DESC_DICT_KEY] = securityDescriptor
            allServices.append(aServiceAsDict)
        return allServices

    def getServicesByServiceStartName(self, serviceType=SERVICE_WIN32, serviceState=SERVICE_STATE_ALL, withConfig=True, withSD=True):
        '''
        Get all services by service start name (the account that the service process will be logged on as when it runs)

        All service start name are returned in lower case
        :return: None if an error. Otherwise returns a dictionary {"ServiceStartName1":[{'ServiceName': 'AeLookupSvc', etc}, etc], etc}
        '''
        details = {}
        logging.debug("Get services by service start name")
        services = self.enumServicesStatus(serviceType=serviceType, serviceState=serviceState, groupName=None, serviceStartName=None, withConfig=withConfig, withSD=withSD)
        if services == None:
            return None
        else:
            for aService in services:
                currentServiceStartName = str.lower(aService['ServiceStartName'])
                if currentServiceStartName not in details:
                    details[currentServiceStartName] = []
                details[currentServiceStartName].append(aService)
        return details

    def printServicesByServiceStartName(self, serviceType=SERVICE_WIN32, serviceState=SERVICE_STATE_ALL, withConfig=True, withSD=True):
        """
        Print all services by service start name (the account that the service process will be logged on as when it runs)
        Return False if an error. Otherwise True
        """
        logging.debug("Printing all services by service start name")
        servicesByServiceStartName = self.getServicesByServiceStartName(serviceType, serviceState, withConfig, withSD)
        if servicesByServiceStartName == None:
            return False
        for aServiceStartName in sorted(servicesByServiceStartName.keys()):
            if aServiceStartName == '':
                print("- {0}:".format("Current log on user"))
            else:
                print("- {0}:".format(repr(aServiceStartName)))
            for aService in servicesByServiceStartName[aServiceStartName]:
                print("    - {0}: ({1})".format(repr(aService['ServiceName']), self.CURRENT_STATE_MAPPING[aService['CurrentState']]))
        return True

    def printServices(self,
                      serviceType=SERVICE_WIN32,
                      serviceState=SERVICE_STATE_ALL,
                      groupName=None,
                      ):
        """
        See enumServicesStatus()
        Return True if ok or None
        """
        logging.debug("Trying to print all services on {0}...".format(repr(self.target)))
        services = self.enumServicesStatus(serviceType=SERVICE_WIN32,
                                           serviceState=SERVICE_STATE_ALL,
                                           groupName=None)
        if services == None:
            return None
        for aService in services:
            self.printAService(aService)
        return True

    def printAService(self, aService):
        """
        Print a Service dictionary
        """
        print("-" * 40)
        for aK in aService:
            if isinstance(aService[aK],dict):
                print("- {0}:".format(repr(aK)))
                for aCK in aService[aK]:
                    print("  - {0}: {1}".format(aCK, repr(aService[aK][aCK])))
            elif isinstance(aService[aK], list):
                print("- {0}:".format(repr(aK)))
                for e in aService[aK]:
                    print("  - {0}".format(e))
            else:
                if aK == 'CurrentState':
                    print("- {0}: {1} ({2})".format(repr(aK), repr(aService[aK]), self.CURRENT_STATE_MAPPING[aService[aK]]))
                else:
                    print("- {0}: {1}".format(repr(aK), repr(aService[aK])))
        print("-" * 40)

    def changeServiceConfigFromHandle(self,
                                      spscHandle,
                                      serviceType=SERVICE_NO_CHANGE,
                                      startType=SERVICE_NO_CHANGE,
                                      errorControl=SERVICE_NO_CHANGE,
                                      binaryFile=None,
                                      loadOrderGroup=None,
                                      fetchTag=None,
                                      serviceDeps=None,
                                      acctName=None,
                                      password=None,
                                      displayName=None
                                      ):
        '''
        Changes the configuration parameters of a service.
        :param spscHandle:
        :param serviceType:
        :param startType:
        :param errorControl:
        :param binaryFile:
        :param loadOrderGroup:
        :param fetchTag:
        :param serviceDeps:
        :param acctName:
        :param password:
        :param displayName:
        :return: False if an error, or True if no problem
        '''
        try:
            ChangeServiceConfigW(spscHandle,
                                           serviceType,
                                           startType,
                                           errorControl,
                                           binaryFile,
                                           loadOrderGroup,
                                           fetchTag,
                                           serviceDeps,
                                           acctName,
                                           password,
                                           displayName
                                      )
        except Exception as e:
            logging.error("Impossible to change Service Config From Handle: {0}".format(e))
            return False
        return True

    def changeServiceConfigFromName(self,
                                    serviceName,
                                    serviceType=SERVICE_NO_CHANGE,
                                    startType=SERVICE_NO_CHANGE,
                                    errorControl=SERVICE_NO_CHANGE,
                                    binaryFile=None,
                                    loadOrderGroup=None,
                                    fetchTag=None,
                                    serviceDeps=None,
                                    acctName=None,
                                    password=None,
                                    displayName=None
                                    ):
        """
        Changes the configuration of an existing service.

        Open the handle of serviceName. Change configuration according to parameters and close handle when it is
        finished.

        See changeServiceConfigFromHandle() for details
        Return None if an error. Otherwise return True
        """
        logging.debug("Trying to change the configuration of the service {0}...".format(repr(serviceName)))
        spscHandle = self.openService(serviceName=serviceName, desiredAccess=SC_MANAGER_ALL_ACCESS)
        if spscHandle == None:
            return None
        status = self.changeServiceConfigFromHandle(spscHandle,
                                            serviceType ,
                                            startType ,
                                            errorControl ,
                                            binaryFile ,
                                            loadOrderGroup ,
                                            fetchTag ,
                                            serviceDeps ,
                                            acctName ,
                                            password ,
                                            displayName)
        if status == None:
            return None
        self.closeThisHandle(spscHandle)
        logging.debug("Config of the service {0} with Service Manager on target {1} has been modified".format(repr(serviceName),repr(self.target)))
        return True

    def createService(self,
                   serviceName,
                   displayName = None,
                   desiredAccess = SERVICE_ALL_ACCESS,
                   serviceType = SERVICE_WIN32_OWN_PROCESS,
                   startType = SERVICE_DEMAND_START,
                   errorControl = SERVICE_ERROR_IGNORE,
                   binaryPathName = None,
                   loadOrderGroup = None,
                   dependencies = None,
                   serviceStartName = None,
                   password = None):
        """
        Creates a service object and adds it to the specified service control manager database.

        SC_MANAGER_CREATE_SERVICE access right is required.
        :param serviceName:
        :param displayName:
        :param desiredAccess:
        :param serviceType:
        :param startType:
        :param errorControl:
        :param binaryPathName:
        :param loadOrderGroup:
        :param dependencies:
        :param serviceStartName:
        :param password:
        :return: None if an error. Otherwise, returns hService

        TODO: manage tagId
        """
        tagId = None
        serviceName = bytes(serviceName, encoding="utf-8")
        if displayName != None:
            displayName = bytes(displayName, encoding="utf-8")
        if binaryPathName != None:
            binaryPathName = bytes(binaryPathName, encoding="utf-8")
        if serviceStartName != None:
            serviceStartName = bytes(serviceStartName, encoding="utf-8")
        if password != None:
            password = bytes(password, encoding="utf-8")
        logging.debug("Trying to create service {0}".format(repr(serviceName)))
        hService = CreateServiceA(self.scHandle, serviceName, displayName, desiredAccess, serviceType, startType,
                                   errorControl, binaryPathName, loadOrderGroup, tagId , dependencies,
                                   serviceStartName, password)
        if hService == None or hService==0:
            logging.error("Impossible to create the service {0}: {1}".format(repr(serviceName), getLastErrorMessage()))
            return None
        logging.debug("Service {0} created on {1}".format(repr(serviceName), self.target))
        return hService

    def deleteServiceFromHandle(self, spscHandle):
        """
        Delete a service from handle

        DELETE access right is required.
        :param spscHandle:
        :return: Tue if ok, or False if an error
        """
        logging.debug("Deleting service from handle...")
        try:
            DeleteService(spscHandle)
        except Exception as e:
            logging.error("Impossible to Delete service from handle: {0}".format(e))
            return False
        logging.debug("Service deleted from handle")
        return True

    def deleteServiceFromName(self, serviceName):
        """
        Delete service from service name.

        DELETE access right is required.
        :param serviceName:
        :return: Tue if ok, or False if an error
        """
        logging.debug("Trying to delete the service {0}...".format(repr(serviceName)))
        spscHandle = self.openService(serviceName=serviceName, desiredAccess=SERVICE_ACCESS_MASK.DELETE)
        if spscHandle == None:
            return None
        status = self.deleteServiceFromHandle(spscHandle)
        if spscHandle == False:
            logging.error("Impossible to delete service {0}".format(repr(serviceName)))
            return False
        logging.debug("Service {0} deleted".format(repr(serviceName)))
        return True

    def controlServiceFromHandle(self, spscHandle, controlCode):
        """
        Sends a control code to a service.
        :param spscHandle:
        :param controlCode: SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_STOP, etc
        :return: Return None if an error or returns ServiceStatus object
        This fonction returns the structure only when ControlService returns one of the following error
        codes: NO_ERROR, ERROR_INVALID_SERVICE_CONTROL, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, or ERROR_SERVICE_NOT_ACTIVE.
        Otherwise, the structure is not filled in and None is returned.
        """
        logging.debug("Sending a control code to service with handle...")
        serviceStatus = SERVICE_STATUS()
        try:
            ControlService(spscHandle, controlCode, byref(serviceStatus))
        except WindowsError as e:
            if e.winerror == ERROR_INVALID_SERVICE_CONTROL:
                logging.debug("ControlService error code returned: ERROR_INVALID_SERVICE_CONTROL")
            elif e.winerror == ERROR_SERVICE_CANNOT_ACCEPT_CTRL:
                logging.debug("ControlService error code returned: v")
            elif e.winerror == ERROR_SERVICE_NOT_ACTIVE:
                logging.debug("ControlService error code returned: ERROR_SERVICE_NOT_ACTIVE")
            else:
                return None
        except Exception as e:
            logging.error("Impossible to control the service from handle: {0}".format(e))
            return None
        logging.debug("Control code sent to handle with handle")
        sStatusObject = ServiceStatus(serviceStatus)
        logging.debug("Service Status: {0}".format(str(sStatusObject)))
        return sStatusObject

    def controlServiceFromName(self, serviceName, controlCode, desiredAccess=SERVICE_ACCESS_MASK.SERVICE_ALL_ACCESS):
        """
        Sends a control code to the service
        :param serviceName:
        :param controlCode: SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_STOP, etc
        :return: Return None if an error or returns SERVICE_STATUS structure
        """
        logging.debug("Sending a control code to service {0}...".format(repr(serviceName)))
        spscHandle = self.openService(serviceName=serviceName, desiredAccess=desiredAccess)
        if spscHandle == None:
            return None
        serviceStatus = self.controlServiceFromHandle(spscHandle, controlCode)
        if serviceStatus == None:
            logging.error("Impossible to send a control code to service {0}".format(repr(serviceName)))
            return None
        logging.error("Control code sent to service {0}".format(serviceName))
        return serviceStatus

    def startServiceFromHandle(self, spscHandle, numServiceArgs=0, serviceArgVectors=None, noError=False):
        """
        Starts a service

        When noError is enabled, no error is printed and it returns True if one of these following errors occured:
        - error 1053 the service did not respond to the start or control request in a timely fashion
        :param spscHandle:
        :param numServiceArgs:
        :return: Return True or False
        """
        logging.debug("Starting service from handle...")
        try:
            StartService(spscHandle, numServiceArgs, serviceArgVectors)
        except WindowsError as e:
            if e.winerror == ERROR_SERVICE_REQUEST_TIMEOUT:
                #error 1053 the service did not respond to the start or control request in a timely fashion
                logging.debug("Message returned by Service Manager but which is not managed as an error: {0}".format(e))
                pass
            else:
                logging.error("Impossible to start service from handle: {0}".format(e))
                return False
        except Exception as e:
            logging.error("Impossible to start service from handle: {0}".format(e))
            return False
        logging.debug("Service started from handle")
        return True

    def startServiceFromName(self, serviceName, numServiceArgs=0, serviceArgVectors=None, noError=False):
        """
        Start service from service name.

        When noError is enabled, no error is printed and it returns True if one of these following errors occured:
        - error 1053 the service did not respond to the start or control request in a timely fashion
        :return: Tue if ok, or False if an error
        Todo: close the handle at the end
        """
        logging.debug("Trying to start the service {0}...".format(repr(serviceName)))
        spscHandle = self.openService(serviceName=serviceName, desiredAccess=SERVICE_ACCESS_MASK.SERVICE_START)
        if spscHandle == None:
            return None
        status = self.startServiceFromHandle(spscHandle, numServiceArgs, serviceArgVectors, noError)
        if status == False:
            logging.error("Impossible to start service {0}".format(repr(serviceName)))
            return False
        logging.debug("Service {0} started".format(repr(serviceName)))
        return True

    def executeBinViaCreate(self, binaryPathName, serviceName, displayName=None, serviceStartName=None, nbRetryDelete=3):
        """
        Execute a command (as SYSTEM by default)

        Create a service, start service with specified command, delete service
        Try to delete the created service 3 timle maximum at the end (and sleep few scds).
        :param cmd:
        :return:
        """
        logging.debug("Trying to execute your bin {0} via service creation".format(repr(binaryPathName)))
        hService = self.createService(serviceName=serviceName,
                                       displayName = displayName,
                                       desiredAccess = SERVICE_ALL_ACCESS,
                                       serviceType = SERVICE_WIN32_OWN_PROCESS,
                                       startType = SERVICE_DEMAND_START,
                                       errorControl = SERVICE_ERROR_IGNORE,
                                       binaryPathName = binaryPathName,
                                       loadOrderGroup = None,
                                       dependencies = None,
                                       serviceStartName = serviceStartName,
                                       password = None)
        if hService == None:
            logging.error("Impossible to create the service for executing your bin {0}".format(repr(binaryPathName)))
            return False
        status=self.startServiceFromHandle(hService, noError=True)
        if status == False:
            logging.error("Impossible to start the service for executing your bin {0}".format(repr(binaryPathName)))
            return False
        for i in range(nbRetryDelete):
            logging.debug("Sleeping {0} scds".format(i))
            time.sleep(i)
            status = self.deleteServiceFromHandle(hService)
            if status == False:
                logging.warning("Impossible to delete the service for executing your bin {0}".format(repr(binaryPathName)))
            else:
                break
        return True

    def closeThisHandle(self, handle):
        """
        Close connection of the service or SCM handle
        Returns True or False
        """
        if self.scHandle == None:
            return False
        try:
            CloseServiceHandle(handle)
        except Exception as e:
            logging.error("Impossible to close handle: {1}".format(e))
            return False
        logging.debug("Handle {0} closed".format(repr(handle)))
        return True

    def closeSCMHandle(self):
        """
        Close SCM handle
        Returns True or False
        """
        if self.scHandle == None:
            return False
        status = self.closeThisHandle(self.scHandle)
        if status == False:
            return False
        else:
            self.scHandle = None
            return True