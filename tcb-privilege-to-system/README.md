# SeTcbPrivilege to SYSTEM, then a new local admin

Full writeup: [jperezduerto.info/techniques/tcb-privilege-to-system](https://jperezduerto.info/techniques/tcb-privilege-to-system/)

A process that already holds **SeTcbPrivilege** can borrow the SYSTEM logon
session, create a service that runs as SYSTEM, and use it to add a new local
administrator, without ever knowing a password. This is a local privilege
escalation primitive, not a remote exploit and not a way to obtain
SeTcbPrivilege in the first place. The article covers the mechanism, where it
applies, and how a defender detects and closes it.

## Files

- `TcbElevationAddAdmin.cpp` : enables SeTcbPrivilege, hooks the SSPI credential
  call to the SYSTEM logon LUID (`0x3E7`), opens the Service Control Manager as
  SYSTEM, and runs a one-shot service whose payload creates an account and adds
  it to the local Administrators group.

## Build

From an x64 Native Tools command prompt (MSVC) on Windows:

```
cl /EHsc /W4 TcbElevationAddAdmin.cpp Secur32.lib Advapi32.lib
```

Cross-compiling from Linux with MinGW-w64:

```
x86_64-w64-mingw32-g++ TcbElevationAddAdmin.cpp -o TcbElevationAddAdmin.exe -lsecur32 -ladvapi32
```

MinGW ships a thinner `sspi.h` than the Windows SDK, so if the SSPI calls fail
to resolve, build with MSVC instead; it is the reliable path for this one.

If a smaller binary is ever needed, the compiled executable can be compressed
with [UPX](https://upx.github.io/), a well known public executable packer.
Packing is not required for the technique to work and is not covered here.

## Usage

```
TcbElevationAddAdmin.exe [username] [password]
```

With no arguments it uses the documented defaults in the source. Starting the
temporary service returns error `1053` (the service did not respond in time):
that is expected, the payload is a plain command and not a real service, so it
never reports status. The account is still created. Verify with:

```
net localgroup administrators
```

## Cleanup

The tool deletes its temporary service but leaves the account. Remove it when
you are done:

```
net localgroup administrators <username> /delete
net user <username> /delete
```

## Defense

The whole chain has one precondition: a context holds **SeTcbPrivilege** (the
"Act as part of the operating system" user right) that should not. Remove that
and the technique has nothing to stand on.

- **Audit who holds the right.** Check Group Policy at Computer Configuration >
  Windows Settings > Security Settings > Local Policies > User Rights
  Assignment > "Act as part of the operating system". On a healthy server the
  list is empty. On a running service account, `whoami /priv` shows it as
  `SeTcbPrivilege`. Remove it from every account and service that does not
  strictly require it, which is almost everything.
- **Run services and consoles least privileged.** The common delivery path is a
  scripting or admin console hosted by a privileged service (for example an
  application server with a Groovy or script console). Run that service under a
  dedicated low-privilege account that does not hold SeTcbPrivilege and is not
  LocalSystem, and restrict who can reach the console.
- **Treat any account that must keep the right as tier 0.** Restrict its logon
  rights, rotate its secret, and monitor it the way you would a domain admin.
- **Watch the Administrators group.** Alert on membership changes to the local
  Administrators group; a new member you did not provision is the outcome this
  technique is trying to reach.

Prove a fix with two checks: a legitimate service can still be installed and
managed by the accounts meant to do that, and from the previously abusable
context, acquiring a credential handle for another logon session is now
refused and no transient service or new admin appears in the logs.

## Detection

The chain is loud. It leaves a short, specific trail:

- **Service install** in the System log (event `7045`), often with a binary
  path that points at a command interpreter or a temp directory, existing for
  only a few seconds.
- **Account created** in the Security log (`4720`) and a **member added to a
  security-enabled local group** (`4732`) for Administrators
  (`S-1-5-32-544`), close together in time.
- Both of the above happen under the **SYSTEM** subject (`S-1-5-18`), because
  the service ran as LocalSystem.

Any one is ordinary in isolation. The sequence, under SYSTEM, inside a minute,
is the signature.

A ready-to-tune Sigma ruleset is in
[`detection/sigma-tcb-add-admin.yml`](detection/sigma-tcb-add-admin.yml): two
atomic rules (the suspicious service install, and the Administrators addition
by SYSTEM) plus a temporal correlation that fires when both land on the same
host within one minute. Allowlist any legitimate SYSTEM-context administration
in your environment to keep the correlation rule clean.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. Running this against a system you are not
authorized to test is illegal in most places.
