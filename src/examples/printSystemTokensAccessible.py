# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from impersonate import Impersonate
from utils import *

configureLogging()
imp = Impersonate()
print("Print limited information about all 'nt authority\system' tokens accessible and which can be impersonated:")
imp.printSystemTokensAccessible(targetPID=None,
                                oneMaxByPid=False,
                                impersonationPossibleOnly=True,
                                printFull=False)