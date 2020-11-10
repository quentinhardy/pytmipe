# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from impersonate import Impersonate
from utils import *

configureLogging()
imp = Impersonate()
imp.impersonateViaCreds(login='theACCOUNT-NAME',
                        password='thePWD',
                        domain="theDOMAIN",
                        logonType=LOGON32_LOGON_INTERACTIVE,
                        logonProvider=LOGON32_PROVIDER_DEFAULT)
imp.printCurrentThreadEffectiveToken(printFull=False, printLinked=False)
imp.terminateImpersonation()