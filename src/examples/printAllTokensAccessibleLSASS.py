# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from impersonate import Impersonate
from utils import *

configureLogging()
pid = getPIDfromName('lsass.exe')
imp = Impersonate()
imp.printAllTokensAccessible(targetPID=pid, printFull=False, printLinked=False, _useThreadMethod=False)