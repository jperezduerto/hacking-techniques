# Loot lives in backups, connection managers, and keyrings

Full writeup: [jperezduerto.info/techniques/credential-stores-backups-connection-managers](https://jperezduerto.info/techniques/credential-stores-backups-connection-managers/)

Most credentials are found, not cracked: a leaked backup that shipped the live
database, a connection manager that saved every host's password, a readable
keyring that decrypts a vault with no cracking. Run `loot-sweep.sh` on every
foothold before hunting a kernel exploit.

## Leaked backups ship live data

```bash
sqlite3 database.sqlite '.schema users'
sqlite3 database.sqlite 'select email,password,api_token from users'
```

32-hex with no `$2y$` and no salt = unsalted MD5 (one rockyou pass); `api_token`
is often plaintext. Verify your wordlist actually downloaded before trusting a
"nothing cracked" result.

## Connection managers

| Store | Tool | Opens via |
|---|---|---|
| `sessions-backup.dat` | Solar-PuTTY | session password, or crack (weak KDF) |
| `confCons.xml` | mRemoteNG | decrypt stored secret |
| `sitemanager.xml`/`recentservers.xml` | FileZilla | base64, not encrypted |
| `*.rdg` | RDCMan | DPAPI under the saving user |
| PuTTY reg keys | PuTTY | `ProxyPassword` cleartext |
| `*.ppk`, `id_rsa` | SSH | `ssh2john` |

The store password is often reused as the admin's app password, recoverable
from the app's own DB. Recovered creds are often higher-privileged: test `su -`
locally.

## Readable keyrings

```bash
cp -r /home/VICTIM/.gnupg /dev/shm/h && chmod -R 700 /dev/shm/h/.gnupg
gpg --homedir /dev/shm/h/.gnupg -d /home/VICTIM/backup/keyvault.gpg   # no-passphrase service keys
```

`--homedir` makes the victim's own key decrypt the blob. Same for a readable
`id_rsa`/`.kdbx`: reuse, not crack.

## Defense

Backups must not carry live secrets (scrub, encrypt, never web-expose; hash with
bcrypt/argon2, not MD5); do not save creds in connection managers on shared
hosts (and never reuse the store password); passphrase-protect keys and keep
`~/.gnupg`/`~/.ssh`/`.kdbx` unreadable by others; least privilege contains it.

## Detection

Reads of session-store files by non-owners; a copy of another user's `.gnupg`/
`.ssh` into `/dev/shm`; an unauthenticated backup download; sustained
`hashcat`/`john` CPU or a wordlist fetch.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission.
