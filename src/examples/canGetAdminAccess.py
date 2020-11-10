# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import sys
sys.path.append('../')
from impersonate import Impersonate
from utils import *

configureLogging()
imp = Impersonate()
print("Is current user can have administration access", imp.canGetAdminAccess())