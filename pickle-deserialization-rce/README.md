# Unpickling is still RCE

Full writeup: [jperezduerto.info/techniques/pickle-deserialization-rce](https://jperezduerto.info/techniques/pickle-deserialization-rce/)

`pickle.load` on data you can influence runs code as whoever loads it. The sink
is old; the hiding places are current. Three modern sinks, then how to stop
trusting pickle. `reduce_demo.py` shows the `__reduce__` mechanism with a
harmless payload (it runs `id`), so you can see it fire and see a safe loader
reject it.

## The mechanism

```python
import os
class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pickle-proof",))   # harmless proof
```

Any `pickle.load`, `torch.load`, `joblib.load`, `pandas.read_pickle`, or a cache
that stores pickles, reading attacker-influenced bytes, is RCE as the loader.

## Three modern sinks

- **Writable Django FileBasedCache dir**: overwrite a `.djcache` entry with a
  malicious pickle; the next `cache.get` runs it as the web user. Fix: the cache
  dir must not be writable by a lower-privileged user.
- **ML artifact pipelines (ClearML < 1.14.3, CVE-2024-24590)**: `Artifact.get()`
  unpickles an uploaded artifact, so a reviewer or scheduler runs your code as
  their identity. Fix: patch; prefer non-executing model formats (safetensors).
- **"We scan the pickle first" wrappers**: the guard parses its scanner's output
  wrong (tests a top-level field that is always `null`) and passes everything.
  Fix: parse the field the scanner populates, fail closed, unit-test with a
  known-bad file.

## Defense

Do not unpickle across a trust boundary (use JSON / a schema / safetensors);
lock file permissions on cache and model dirs; if you must scan, parse the
verdict correctly and fail closed; patch MLOps tooling.

## Detection

A Python web/worker process spawning a shell right after a cache read or
artifact fetch; a `.djcache`/`.pkl`/checkpoint modified by the wrong uid.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. The demo payload runs `id`.
