import sys
sys.path.append('../')
from impersonate import Impersonate
from utils import *

configureLogging()
imp = Impersonate()
imp.printAllTokensAccessibleWithRecursiveImpersonation()