PYTMIPE
====

__PYTMIPE__ (PYthon library for Token Manipulation and Impersonation for Privilege Escalation) is a Python library for manipulating Windows tokens and managing impersonations in order to gain more privileges on Windows. It implements some exploits for local privilege escalations on Windows.


Features
====

The following non-exhaustive list shows some features implemented in pytmipe:
* Token and privileges management:
  * get, enable or disable privilege(s) on token for current or remote thread
  * get local or remote token information
  * get effective token for current thread (impersonation or primary token)
* get many information about selected token(s):
  * elevation type
  * impersonation type
  * Linked token with details
  * SID
  * ACLs
  * default groups
  * primary group
  * owner
  * privileges
  * source
  * etc
* __List all tokens which are accessible__ (primary & impersonation tokens) from current thread.
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
However, some features of pytmipe still use *pywin32* (e.g. *pythoncom*) by lack of time.
For example, Windows services management and token manipulation/management is done with ctypes only but Windows Task Scheduler management is done over *pythoncom*/*win32com* (*pywin32*).

Examples
====

Get all details of each accessible token (primary & impersonation) of all processes running locally on the system with the "handle" method:
```python
imp = Impersonate()
imp.printAllTokensAccessible(targetPID=None, printFull=True, printLinked=True, _useThreadMethod=False)
```

List token(s) by account name (SID) in process with pid 548 and use "handle" method:
```python
imp = Impersonate()
imp.printTokensAccessibleByAccountNameAndPID(targetPID=548, _useThreadMethod=False)
```

List all token(s) by account name (SID) in all processes and use "thread" method:
```python
imp = Impersonate()
imp.printTokensAccessibleByAccountNameAndPID(targetPID=None, _useThreadMethod=True)
```

Impersonate the first *nt authority\system* token (primary or impersonation) found in a process running locally:
```python
imp = Impersonate()
imp.searchAndImpersonateFirstSystemToken(targetPID=None)
```

Exploit the "Printer Bug" for privilege escalation from *SeImpersonatePrivilege* to *nt authority\system*:
```python
esc = Escalation()
esc.namedPipeImpersonationViaPrinterBug()
```
  
Exploit the RPCSS service for privilege escalation from *SeImpersonatePrivilege* to *nt authority\system*:
```python
esc = Escalation()
esc.namedPipeImpersonationViaRPCSS()
```

Re give full power (privileges) with task scheduling and named pipe impersonation:
```python
esc = Escalation()
esc.reGiveMePower(debug=True)
```

Privilege escalation from Local Administrator to *nt authority\system* with Windows Task Scheduler
```python
esc = Escalation()
esc.namedPipeImpersonationViaTaskScdh()
```

Parent PID Spoofing (pid 400) and executre cmd.exe
```python
esc = Escalation()
esc.spoofPPID(500, "c:\\windows\\system32\\cmd.exe")
``` 
  
HOW TO USE
====
See source code.
Normally, I have well documented the source code...

Donation
====
If you want to support my work doing a donation, I will appreciate a lot:

Via BTC: 36FugL6SnFrFfbVXRPcJATK9GsXEY6mJbf
