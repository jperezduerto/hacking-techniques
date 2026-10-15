# Windows local privilege escalation: read-only enumeration with built-ins.
# Surfaces the misconfiguration path; it does NOT exploit anything and writes
# nothing. Authorized and educational use only.
# Writeup: https://jperezduerto.info/techniques/windows-local-privesc/

function Section($t) { Write-Host "`n=== $t ===" }

Section "Orientation"
whoami /all
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List

Section "Token privileges"
whoami /priv

Section "Services: unquoted paths outside C:\Windows"
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^C:\\Windows' } |
  Select-Object Name, StartMode, PathName | Format-Table -AutoSize

Section "Scheduled tasks (non-Microsoft)"
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } |
  Select-Object TaskName, TaskPath, State | Format-Table -AutoSize

Section "AlwaysInstallElevated"
foreach ($h in 'HKLM','HKCU') {
  (Get-ItemProperty "${h}:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
}

Section "Stored credentials / autologon"
cmdkey /list
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue

Section "Patch level"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, InstalledOn

Section "Local administrators"
Get-LocalGroupMember Administrators -ErrorAction SilentlyContinue

Section "Network"
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPAddress
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess

Write-Host "`nDone. Read each result for the privilege boundary it crosses; the writeup maps each finding to its hop."
