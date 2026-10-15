# DCSync: replicating secrets out of Active Directory

Full writeup: [jperezduerto.info/techniques/dcsync-replication-abuse](https://jperezduerto.info/techniques/dcsync-replication-abuse/)

DCSync abuses the Active Directory replication protocol (MS-DRSR) to pull
password hashes, including `krbtgt`, from a domain controller without running
code on it. The caller just has to hold the directory replication rights and
then make the same `IDL_DRSGetNCChanges` request a real replica DC makes.
MITRE ATT&CK T1003.006.

This folder is a **teaching skeleton**, not a finished tool. It shows the real
call flow and marks the two parts you implement yourself. The point is to learn
the protocol, not to run someone else's binary. The canonical, complete, open
implementations already exist (Impacket `secretsdump.py`, Mimikatz
`lsadump::dcsync`); this is here to make the mechanism legible.

## Files

- `dcsync.c` : the skeleton. Builds an authenticated, privacy-sealed RPC binding
  to a DC's `drsuapi` interface (this part is real and complete), then documents
  the `IDL_DRSBind` -> `IDL_DRSGetNCChanges` single-object replication request
  and marks where the returned secrets are decrypted.
- `detection/sigma-dcsync-nondc-replication.yml` : a Sigma rule for the defense
  side, replication requested by a principal that is not a domain controller.

## Precondition

A controlled principal that already holds **both** `DS-Replication-Get-Changes`
and `DS-Replication-Get-Changes-All` on the domain object. DCSync is what you do
once you hold those rights; it is not a way to get them. Enumerate who holds
them with BloodHound before assuming you do.

## Build

This is left deliberately as two steps, because step 1 is where you learn how
the wire protocol is actually defined.

1. **Generate the RPC stubs.** `dcsync.c` includes `drsuapi_h.h`, which does not
   ship here. Produce it (and the client stub) by compiling the public MS-DRSR
   IDL with the Microsoft IDL compiler:

   ```
   midl ms-drsr.idl
   ```

   The IDL and its structure definitions are in the open
   [MS-DRSR specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/).
   Samba and Impacket also carry readable transcriptions of the same
   interface if you want a cross-reference while you work.

2. **Compile and link.** From an x64 Native Tools command prompt (MSVC):

   ```
   cl /EHsc /W4 dcsync.c drsuapi_c.c rpcrt4.lib
   ```

   (`drsuapi_c.c` is the MIDL-generated client stub from step 1.)

Nothing here is pre-compiled on purpose. If you want a working reference while
you fill in the gaps, read Impacket's `drsuapi.py`; it is the clearest open
version of the same calls.

## Make it your own

The skeleton is incomplete by design, and finishing it is the exercise:

- **Implement STEP C**, the secret decryption, from MS-DRSR section 5.x: pull the
  session key from the authenticated binding and unseal the encrypted attributes
  per the spec. This is the part that turns a protocol call into recovered
  hashes, and writing it yourself is how you actually understand DCSync.
- **Pick your request version.** Windows exposes `GETCHGREQ` V5/V8/V10; choose
  one and advertise the matching client extension in `IDL_DRSBind`. Noticing why
  the versions differ teaches you how the protocol evolved.
- **Choose your output.** Single user vs. whole-NC, which attributes you ask for,
  how you format the result. Build the variant that fits how you work.

"Custom" here means you complete and adapt the scaffold to learn it, not that you
obfuscate it. This is an educational artifact; there is no evasion tradecraft in
this repo.

## Detection and defense

Read this part even if you only came for the code, it is short and it is the
point of the writeup.

DCSync is one of the most detectable high-impact AD techniques when the auditing
is on. On your DCs, with Directory Service Access auditing enabled and a SACL on
the domain object, a DCSync fires **Event 4662** with a Control Access mask
(`0x100`) referencing the replication GUIDs:

- `DS-Replication-Get-Changes`     `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
- `DS-Replication-Get-Changes-All`  `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`

The alert logic: fire when the requesting principal is **not** a domain
controller machine account (whitelist your DCs and known sync services such as
Azure AD Connect and SCCM). See `detection/` for a Sigma rule, and the writeup
for the full prevention and response section. The cheapest prevention is to make
sure no account outside your DCs and sync services holds those replication
rights in the first place.

## Use

Authorized assessment and defensive learning only. See the writeup for scope.
