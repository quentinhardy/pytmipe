# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from impersonate import Impersonate
from utils import *

configureLogging()
imp = Impersonate()
print("Print limited information about all 'nt authority\system' tokens accessible:")
imp.printTokensAccessibleFilter(targetPID=None,
                                filter={'intlvl':'System', 'sid':'S-1-5-18'},
                                printFull=False,
                                printLinked=False,
                                _useThreadMethod=False)