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

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. Running this against a system you are not
authorized to test is illegal in most places.
