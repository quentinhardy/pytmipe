# -*- coding: UTF-8 -*-
# By Quentin HARDY (quentin.hardy@protonmail.com) - bobsecq

import PyInstaller.__main__
import tempfile
import shutil
import os

pyScript = "namedPipeImpersonationSystemViaPrinterBug.py"

workpath = os.path.join(tempfile.gettempdir(),'build')

print("Workpath set to {0}".format(repr(workpath)))
PyInstaller.__main__.run([
    '--onefile',
    '--paths={0}'.format("..\\external\\dlls\\"),
    '--paths={0}'.format("..\\"),
    '--hidden-import={0}'.format("ctypes.wintypes"),
    #'--hidden-import={0}'.format("pywintypes"),
    #'--hidden-import={0}'.format("pythoncom"),
    #'--hidden-import={0}'.format("win32com"),
    '--exclude-module={0}'.format("pywintypes"),
    '--exclude-module={0}'.format("pythoncom"),
    '--exclude-module={0}'.format("win32com"),
    '--exclude-module={0}'.format("win32comext"),
    '--workpath={0}'.format(workpath),
    '--specpath={0}'.format(workpath),
    '--log-level=DEBUG',
    '--clean',
    pyScript,
])
shutil.rmtree("./__pycache__")
