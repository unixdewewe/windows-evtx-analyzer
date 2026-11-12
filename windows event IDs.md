                            WINDOWS EVENT IDs

---

### 1. Logon / Logoff Events

* **4624** – An account was successfully logged on (also described as *Successful logon*).


* **4625** – An account failed to log on (also described as *Failed logon*).


* **4634** – The logoff process was completed for a user (also described as *Logoff*).


* **4647** – A user initiated the logoff process (also described as *User initiated logoff*).


* **4648** – A logon was attempted using explicit credentials (also described as *Logon using explicit credentials*).


* **4672** – Special privileges have been assigned to a new logon (also described as *Special privileges assigned to new logon*).


* **4723** – An attempt was made to change an account’s password.


* **4724** – An attempt was made to reset an account’s password.


* **4740** – A user account was locked out.


* **4767** – A user account was unlocked.


* **4779** – A session was disconnected from a Window Station (also described as *Session disconnected*).


* **4964** – Special groups have been assigned to a new logon (also described as *Special groups assigned to new logon*).


* **5378** – The requested credentials delegation was disallowed by policy.



---

### 2. System Startup / Shutdown

* **4608** – Windows is starting up.


* **4609** – Windows is shutting down.



---

### 3. Authentication & Security Packages

* **4610** – Authentication package loaded.


* **4611** – Trusted logon process registered.


* **4614** – Notification package loaded.


* **4615** – Invalid LPC port use.


* **4616** – System time changed.



---

### 4. Object Access & Registry (Access Events)

* **4656** – A handle to an object was requested (also described as *Handle to object requested*).


* **4657** – A registry value was modified.


* **4658** – A handle to an object was closed.


* **4660** – An object was deleted (also described as *Object deleted*).


* **4663** – An attempt was made to access an object (also described as *Attempt to access an object*).


* **4670** – Permissions on an object were changed.


* **5140** – A network share object was accessed.


* **5142** – A network share object was added.


* **5143** – A network share object was modified.


* **5144** – A network share object was deleted.



---

### 5. Process & Service Events

* **4688** – New process created.


* **4697** – Service installed.



---

### 6. High-Criticality Security Events

* **4618** – Monitored security event pattern occurred.


* **4649** – Replay attack detected.



---

### 7. Active Directory, Account, and Group Events

* **4720** – A user account was created.


* **4722** – A user account was enabled.


* **4725** – A user account was disabled.


* **4726** – A user account was deleted.


* **4727** – A security-enabled global group was created.


* **4728** – A member was added to a security-enabled global group.


* **4729** – A member was removed from a security-enabled global group.


* **4730** – A security-enabled global group was deleted.


* **4731** – A security-enabled local group was created.


* **4732** – A member was added to a security-enabled local group.


* **4733** – A member was removed from a security-enabled local group.


* **4734** – A security-enabled local group was deleted.


* **4735** – A security-enabled local group was changed.


* **4737** – A security-enabled global group was changed.


* **4738** – A user account was changed.


* **4739** – Domain Policy was changed.


* **4741** – A computer account was created.


* **4742** – A computer account was changed.


* **4743** – A computer account was deleted.


* **4744** – A security-disabled local group was created.


* **4745** – A security-disabled local group was changed.


* **4746** – A member was added to a security-disabled local group.


* **4747** – A member was removed from a security-disabled local group.


* **4748** – A security-disabled local group was deleted.


* **4749** – A security-disabled global group was created.


* **4750** – A security-disabled global group was changed.


* **4751** – A member was added to a security-disabled global group.


* **4752** – A member was removed from a security-disabled global group.


* **4753** – A security-disabled global group was deleted.


* **4754** – A security-enabled universal group was created.


* **4755** – A security-enabled universal group was changed.


* **4756** – A member was added to a security-enabled universal group.


* **4757** – A member was removed from a security-enabled universal group.


* **4758** – A security-enabled universal group was deleted.


* **4759** – A security-disabled universal group was created.


* **4760** – A security-disabled universal group was changed.


* **4761** – A member was added to a security-disabled universal group.


* **4762** – A member was removed from a security-disabled universal group.


* **4763** – A security-disabled universal group was deleted.


* **4764** – A group type was changed.


* **5136** – A directory service object was modified.


* **5137** – A directory service object was created.


* **5138** – A directory service object was undeleted.


* **5139** – A directory service object was moved.


* **5141** – A directory service object was deleted.



---

### 8. Auditing Events

* **1100** – The event logging service has shut down.


* **1101** – Audit events have been dropped by the transport.


* **1102** – The audit log was cleared.


* **1104** – The security log is now full.


* **1108** – The event logging service encountered an error while processing an incoming event.


* **4612** – Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.


* **4719** – System audit policy was changed.


* **4907** – Auditing settings on an object were changed.



---

### 9. Microsoft Sysmon (System Monitor) Events

*(Logged under `Microsoft-Windows-Sysmon/Operational`)*

* **Sysmon 1** – Process Creation (Captures full command line, parent process, user, and binary hashes).
* **Sysmon 2** – File Creation Time Change (Tracks explicit modification of file timestamps to hide origin).
* **Sysmon 3** – Network Connection (Logs TCP/UDP connections with source/destination IPs, ports, and parent process).
* **Sysmon 4** – Sysmon Service State Changed (Detects if the monitoring service is stopped or changed).
* **Sysmon 5** – Process Terminated (Logs when a process stops executing).
* **Sysmon 6** – Driver Loaded (Logs drivers loaded into the system, exposing vulnerable or unsigned drivers).
* **Sysmon 7** – Image Loaded / DLL Load (Detects DLL injection and hijacking).
* **Sysmon 8** – CreateRemoteThread (Detects process injection where one process creates a thread in another).
* **Sysmon 9** – RawAccessRead (Detects low-level disk reading behavior bypassing file system APIs).
* **Sysmon 10** – Process Access / OpenProcess (Frequently used to detect LSASS memory dumping / credential harvesting).
* **Sysmon 11** – File Created (Tracks new files written to disk, vital for ransomware and artifact analysis).
* **Sysmon 12 / 13 / 14** – Registry Events (Tracks registry key/value creation, modification, and renaming for persistence mechanisms).
* **Sysmon 15** – FileCreateStreamHash (Detects Alternate Data Streams [ADS] and Mark-of-the-Web bypasses).
* **Sysmon 16** – Sysmon Configuration Change (Audits updates to the active Sysmon config file).
* **Sysmon 17 / 18** – Named Pipe Created / Connected (Tracks Inter-Process Communication used by malware/lateral movement).
* **Sysmon 19 / 20 / 21** – WMI Events (WMI filter, consumer, and binding activity monitoring).
* **Sysmon 22** – DNS Query / DNS Event (Logs DNS queries executed by processes, capturing domain lookups and C2 beaconing).
* **Sysmon 23 / 26** – File Delete (Tracks deleted files and artifacts).
* **Sysmon 25** – Process Tampering (Detects process hollowing/masquerading techniques).

---

### 10. Windows DNS Client & Server Events

*(Network Name Resolution & Server Operations)*

* **DNS Client Events (Operational / Client-side):**
* **1014** – Name Resolution Warning (Logged when the DNS client fails to resolve names for a destination query).


* **DNS Server Events (`Microsoft-Windows-DNS-Server/Operational`):**
* **4000 / 4004** – DNS Server encountered a critical error or startup failure.
* **4015** – DNS Server encountered a critical error with Active Directory.
* **7050 / 7052 / 7053** – Zone transfers and dynamic updates.
