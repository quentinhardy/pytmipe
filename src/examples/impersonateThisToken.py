# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from impersonate import Impersonate
from utils import *
from windef import TokenImpersonation

configureLogging()
imp = Impersonate()
#Get all 'impersonation' tokens wich can be impersonated and which are 'system'
allTokens = imp.getTokensAccessibleFilter(targetPID=None,
                                       filter={'canimpersonate':True, 'sid':'S-1-5-18', 'type':TokenImpersonation},
                                       _useThreadMethod=False)
if allTokens == {} or allTokens==None:
    print("No one token found for impersonation")
else:
    #use the first token of the first pid returned in 'allTokens'
    pid = list(allTokens.keys())[0]
    firstIHandle = allTokens[pid][0]['ihandle']
    imp.printThisToken(allTokens, pid, firstIHandle)
    imp.impersonateThisToken(pid=pid, iHandle=firstIHandle)
    print("Current Effective token for current thread after impersonation:")
    imp.printCurrentThreadEffectiveToken(printFull=False, printLinked=False)
    imp.terminateImpersonation()
    print("Current Effective token for current thread (impersonation finished):")
    imp.printCurrentThreadEffectiveToken(printFull=False, printLinked=False)
