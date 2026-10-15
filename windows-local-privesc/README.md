# Windows local privilege escalation

Full writeup: [jperezduerto.info/techniques/windows-local-privesc](https://jperezduerto.info/techniques/windows-local-privesc/)

Enumerate a Windows host you have a low-privilege shell on using built-ins
(`whoami`, `sc`, `reg`, `schtasks`, `wmic`, PowerShell), then take the
documented hops to Administrator or SYSTEM. For pentesters, with the detection
each step leaves. Exploit code for the named CVE and token classes is not
carried here; this is the misconfiguration surface.

`enum.ps1` bundles the read-only checks into one pass.

## Orientation

```cmd
whoami /all & systeminfo & hostname
```

## Enumeration (built-ins)

```cmd
whoami /priv
wmic service get Name,PathName,StartMode | findstr /i /v "C:\Windows\\"
schtasks /query /fo LIST /v | findstr /i "TaskName Run As"
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul
where /r C:\ unattend.xml sysprep.xml 2>nul
wmic qfe get HotFixID,InstalledOn
net localgroup administrators
```

## From a finding to admin or SYSTEM

Documented hops; the fix line is the point for defenders.

- **Unquoted service path** with a writable gap: drop `C:\Program.exe`, restart
  the service. Fix: quote every service `binPath`.
- **Weak service permissions**: `sc config myservice binPath= "...payload.exe"`
  then restart. Fix: remove `SERVICE_CHANGE_CONFIG`/`WRITE_DAC` from non-admins.
- **Writable service/task binary**: replace the exe, trigger the run. Fix: ACL
  service and task binaries to admins.
- **AlwaysInstallElevated** (both keys `1`): `msiexec /quiet /qn /i evil.msi`
  runs as SYSTEM. Fix: never enable the policy.
- **Token privileges** (`SeImpersonate`/`SeAssignPrimaryToken`): the Potato
  family and PrintSpoofer impersonate SYSTEM. Referenced by name, not carried.
  Fix: keep `SeImpersonate` on as few accounts as possible.
- **SeBackup/SeRestore**: `reg save HKLM\SAM` + `HKLM\SYSTEM`, extract offline.
  Fix: no backup rights for interactive users.
- **Stored creds**: `cmdkey /list`, `unattend.xml`, Winlogon `DefaultPassword`,
  PowerShell history. Fix: scrub them.
- **Kernel/CVEs**: match `systeminfo` + `wmic qfe` to a maintained public
  exploit. No exploit code here; detect the artifacts and patch the build out.

## Detection

Enable 4688 command-line auditing and Sysmon.

- Service: 7045/4697, `sc config`, a binPath in a user-writable dir.
- Scheduled task: 4698/4702, a task action that is a user-writable binary.
- Privilege: 4672/4673; a service account holding or using SYSTEM.
- MSI and lineage: `msiexec` from Temp; Sysmon process-create where a service
  or `msiexec` parents a shell.
- Hive/cred access: `reg save` of SAM/SYSTEM; reads of `unattend.xml` or the
  Winlogon password value.

Correlate: a low-priv logon, then a service reconfig or Temp-path MSI install,
then a process running as SYSTEM.

## Hardening, briefly

Quote service paths and ACL service/task binaries; never set
AlwaysInstallElevated; keep `SeImpersonate`/`SeBackup`/`SeRestore` off low-trust
accounts; scrub unattend and autologon secrets; patch; enable 4688 + Sysmon.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. Enumeration and documented misconfiguration
hops for a host you are authorized to assess, shown with their detection.
