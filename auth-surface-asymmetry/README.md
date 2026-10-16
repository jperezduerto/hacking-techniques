# Auth-surface asymmetry (credentials in plain sight)

Full writeup: [jperezduerto.info/techniques/auth-surface-asymmetry](https://jperezduerto.info/techniques/auth-surface-asymmetry/)

Two cheap wins testers skip. A support/policy page that states the
password-reset convention is a live credential. And a login form that rejects a
credential you trust is one auth surface, not the verdict: the API, SSH, or SMB
on the same app often never checks the flag the form enforced.
`auth-differential.sh` sends one credential pair to the form and the common API
endpoints and reports which accept it.

## Stated policy is the credential

"Reset to the same as the username" means `user:user` for every name;
"new accounts start with Welcome2026!" means that literal, sprayed. Harvest
names from the page, including its images (pasted ticket/chat screenshots show
real usernames).

```bash
netexec smb dc1.domain.local -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

NTLM error usually means the credential is fine and NTLM is disabled: use
Kerberos, do not retire the password.

## The form is one surface

An account can be disabled/locked/expired and still be a valid pair: the form
checks the flag, the API frequently does not. Try the same pair against
`/api/v1/authenticate`, `/api/login`, `/rest/`, `/oauth/token`, `/graphql`,
Basic auth, legacy/mobile routes, and SSH/FTP/SMB/WinRM/LDAP/DB. Convert a
returned token into a session (`?token=...`); ask for a long lifetime so slow
follow-ons do not expire mid-attack.

## Defense

Do not document passwords; enforce auth and account state centrally so every
surface honors the same disabled/locked flag; disabling an account must drop its
API tokens and service access too.

## Detection

A successful API/token auth for an account disabled or just-rejected at the
form (a state mismatch across surfaces); a burst of username==password logins; a
spray following a visit to a help/onboarding page.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission.
