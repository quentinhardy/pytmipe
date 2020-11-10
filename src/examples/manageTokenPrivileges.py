# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from tokenmanager import TokenManager
from impersonate import Impersonate
from utils import *

configureLogging()
imp = Impersonate()
print("Current thread token:")
imp.printCurrentThreadEffectiveToken(printFull=False, printLinked=False)
TokenManager.disableAllUserRights()
#Impersonate.disableAllUserRights() can be used too
print("Current thread token after disabling all privileges:")
imp.printCurrentThreadEffectiveToken(printFull=False, printLinked=False)
TokenManager.enableAllUserRights()
#TokenManager.enableAllUserRights() can be used too
print("Current thread token after enabling all privileges:")
imp.printCurrentThreadEffectiveToken(printFull=False, printLinked=False)
