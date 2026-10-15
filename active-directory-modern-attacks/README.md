# Active Directory: the modern attack surface

Full writeup: [jperezduerto.info/techniques/active-directory-modern-attacks](https://jperezduerto.info/techniques/active-directory-modern-attacks/)

Where modern AD engagements are won: AD Certificate Services (the ESC family),
delegation and RBCD, shadow credentials, coercion-and-relay, modern ticket
forgery, and the newest gMSA/dMSA abuses. Each with its prerequisite, the public
tool that performs it (named, not carried), the detection, and the fix. A Sigma
ruleset for the highest-signal directory changes is in
[`detection/sigma-ad-object-changes.yml`](detection/sigma-ad-object-changes.yml).

Tools referenced: BloodHound/SharpHound, Certipy, Certify, Whisker/pyWhisker,
Rubeus, Impacket (`rbcd.py`, `getST`, `secretsdump`), Coercer, ntlmrelayx.

## The surface

- **ADCS ESC1 / ESC8 / ESC6-16**: template and CA misconfig hand out client-auth
  certs; ESC8 relays a coerced DC to HTTP enrollment. Fix: fix templates, require
  manager approval, disable/bind HTTP enrollment, apply cert-mapping hardening.
- **Shadow credentials**: write `msDS-KeyCredentialLink`, PKINIT, UnPAC-the-hash.
  Fix: restrict and monitor writes to that attribute.
- **RBCD**: write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer, then
  S4U to impersonate. Fix: restrict delegation-attribute writes; monitor.
- **Unconstrained delegation** + DC coercion = DC TGT. Fix: remove it; Protected
  Users; mark sensitive accounts non-delegable.
- **Coercion + relay** (PetitPotam, printer bug, DFSCoerce): force DC auth, relay
  to ADCS or LDAP. Fix: patch, disable NTLM, signing + channel binding (EPA).
- **DACL abuse** (GenericAll/Write, WriteDACL/Owner): resets, group adds, shadow
  creds, targeted Kerberoast. Fix: tiering, least-privilege ACLs, monitor tier-0.
- **Modern tickets** (diamond, sapphire): modify real tickets to dodge golden/
  silver detections. Fix: protect/rotate `krbtgt`, AES-only, PAC validation.
- **gMSA read / dMSA (BadSuccessor, 2025) / timeroasting**: managed-account and
  NTP abuses. Fix: restrict retrieval and dMSA/OU write perms; rotate machine
  passwords.
- **noPac / Zerologon** (`CVE-2021-42278/42287`, `CVE-2020-1472`): patch-only.
  No exploit code here.

## Detection, highest signal

- ADCS issuance 4886/4887 and cert logons (4768 w/ cert) for non-smartcard accts.
- `msDS-KeyCredentialLink` and delegation-attribute writes (5136/4662).
- Coercion RPC (EFSRPC/RPRN/DFSNM) and DC-to-non-DC auth.
- DCSync from a non-DC (4662 replication GUIDs).
- ACL/group/password-reset changes (5136/4728/4732/4756/4724) on tier-0.
- Kerberos anomalies: RC4 downgrade, odd lifetimes, PAC mismatch.

Enable directory-change and Kerberos auditing; feed BloodHound your own data.

## Hardening

Tier administration; fix ADCS templates and bind/disable HTTP enrollment; remove
unconstrained delegation and lock delegation attributes; Protected Users +
non-delegable; SMB/LDAP signing and channel binding, disable NTLM; restrict gMSA/
dMSA/OU writes; protect and rotate `krbtgt`; patch DCs.

## Use

Authorized and educational use only: your own lab, a directory you own, or an
engagement with written permission. An overview of documented techniques with
tools named not carried, paired with detection and remediation.
