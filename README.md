PYTMIPE
====

__PYTMIPE__ (PYthon library for Token Manipulation and Impersonation for Privilege Escalation) is a Python library for manipulating Windows tokens and managing impersonations in order to gain more privileges on Windows. It implements some exploits for local privilege escalations on Windows.


Features
====

The following non-exhaustive list shows some features implemented in pytmipe:
* Token and privileges management:
  * get, enable or disable privilege(s) on token for current or remote thread
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
  * Create Process with a token (specific privileges are required): imeprsoanate a chosen token and create new process
  * __Impersonate first *nt authority\system* token__ found
  * impersonate primary token of remote process with pid
* Escalation methods:
  * __Parent PID Spoofing__ - Handle Inheritance
  * Service Manager via direct command or named pipe impersonation: local administrator to *nt authority\system*
  * Task scheduler via direct command or named pipe impersonation: local administrator to *nt authority\system*
  * WMI job via direct command or named pipe impersonation: local administrator to *nt authority\system*
  * __Printer Bug__: SeImpersonatePrivilege to *nt authority\system*
  * __RPCSS__: SeImpersonatePrivilege to *nt authority\system*
  * __Re enable privileges__ via task scheduling and named pipe impersonation
  
Dependencies
====

*ctypes* is used a maximum of time.
Many features of *pywin32* have been re developped in pytmipe to avoid the use of *pywin32* for better portability.
However, some features of pytmipe still use *pywin32* (e.g. *pythoncom*) by lack of time.
For example, Windows services management and token manipulation/management is done with ctypes only but Windows Task Scheduler management is done over *pythoncom*/*win32com* (*pywin32*).
  
HOW TO USE
====
See source code.
Normally, I have well documented the source code...
