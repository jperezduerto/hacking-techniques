# Hacking techniques

Proof-of-concept code for the techniques I write up at
[jperezduerto.info/techniques](https://jperezduerto.info/techniques/).

Each technique lives in its own folder, named to match its article. The
article explains how the technique works and where it applies; the folder here
holds the runnable proof of concept and build notes.

## Techniques

| Technique | Folder | Article |
|-----------|--------|---------|
| SeTcbPrivilege to SYSTEM, then a new local admin | [`tcb-privilege-to-system/`](tcb-privilege-to-system/) | [Read the writeup](https://jperezduerto.info/techniques/tcb-privilege-to-system/) |
| The Liferay Groovy script console | [`liferay-groovy-console/`](liferay-groovy-console/) | [Read the writeup](https://jperezduerto.info/techniques/liferay-groovy-console/) |
| Living off the land on Linux (local enumeration) | [`linux-living-off-the-land/`](linux-living-off-the-land/) | [Read the writeup](https://jperezduerto.info/techniques/linux-living-off-the-land/) |
| Windows local privilege escalation | [`windows-local-privesc/`](windows-local-privesc/) | [Read the writeup](https://jperezduerto.info/techniques/windows-local-privesc/) |
| Linux container escapes | [`linux-container-escapes/`](linux-container-escapes/) | [Read the writeup](https://jperezduerto.info/techniques/linux-container-escapes/) |
| Windows credential access | [`windows-credential-access/`](windows-credential-access/) | [Read the writeup](https://jperezduerto.info/techniques/windows-credential-access/) |
| Active Directory: the modern attack surface | [`active-directory-modern-attacks/`](active-directory-modern-attacks/) | [Read the writeup](https://jperezduerto.info/techniques/active-directory-modern-attacks/) |
| systemd confinement gotchas (post-exploitation) | [`systemd-confinement-gotchas/`](systemd-confinement-gotchas/) | [Read the writeup](https://jperezduerto.info/techniques/systemd-confinement-gotchas/) |
| Unpickling is still RCE (deserialization) | [`pickle-deserialization-rce/`](pickle-deserialization-rce/) | [Read the writeup](https://jperezduerto.info/techniques/pickle-deserialization-rce/) |
| The curl dot-dot trap (path-traversal false negatives) | [`curl-path-traversal-false-negative/`](curl-path-traversal-false-negative/) | [Read the writeup](https://jperezduerto.info/techniques/curl-path-traversal-false-negative/) |
| Auth-surface asymmetry (credentials in plain sight) | [`auth-surface-asymmetry/`](auth-surface-asymmetry/) | [Read the writeup](https://jperezduerto.info/techniques/auth-surface-asymmetry/) |
| Chrome remote-debugging session theft | [`chrome-remote-debug-session-theft/`](chrome-remote-debug-session-theft/) | [Read the writeup](https://jperezduerto.info/techniques/chrome-remote-debug-session-theft/) |
| disable_functions is config, not a wall (PHP) | [`php-disable-functions-ini-bypass/`](php-disable-functions-ini-bypass/) | [Read the writeup](https://jperezduerto.info/techniques/php-disable-functions-ini-bypass/) |
| ASP.NET ViewState RCE from a leaked machineKey | [`aspnet-viewstate-machinekey-rce/`](aspnet-viewstate-machinekey-rce/) | [Read the writeup](https://jperezduerto.info/techniques/aspnet-viewstate-machinekey-rce/) |
| The in-house thick client is the privesc (.NET deser) | [`dotnet-thick-client-deser-rce/`](dotnet-thick-client-deser-rce/) | [Read the writeup](https://jperezduerto.info/techniques/dotnet-thick-client-deser-rce/) |
| Loot in backups, connection managers, keyrings | [`credential-stores-backups-connection-managers/`](credential-stores-backups-connection-managers/) | [Read the writeup](https://jperezduerto.info/techniques/credential-stores-backups-connection-managers/) |
| SSH tunneling (-L/-R/-D) + tunnelctl helper | [`ssh-tunneling/`](ssh-tunneling/) | [Read the writeup](https://jperezduerto.info/techniques/ssh-tunneling/) |
| Ligolo-ng pivoting (L3 userland VPN) + ligoloctl helper | [`ligolo-ng-pivoting/`](ligolo-ng-pivoting/) | [Read the writeup](https://jperezduerto.info/techniques/ligolo-ng-pivoting/) |

## Use

This code is published for learning and for authorized security work only:
your own systems, a lab you control, or an engagement with written permission.
Running it against a system you are not authorized to test is illegal in most
places. You are responsible for how you use it.
