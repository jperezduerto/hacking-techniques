#!/usr/bin/env python3
"""
hivekit: the boring glue for practicing offline registry-hive parsing.

It does ONE thing: take base64 text (one file, or several parts you name in
order), strip any certutil `-----BEGIN/END CERTIFICATE-----` framing, decode it
back to the original bytes, and confirm the result is a real registry hive by
checking the leading `regf` magic. It then prints the size and hive type.

It is deliberately inert. It does not connect to anything, does not read the
registry, does not save or parse any secret. It is the reassembly step you would
otherwise write by hand while learning how SAM/SYSTEM/SECURITY come apart and go
back together. Parsing the decoded hive into hashes is a separate, well-known
tool (Impacket secretsdump), intentionally not included here.

Educational and authorized use only. Writeup:
https://jperezduerto.info/techniques/offline-registry-hive-dumping/

    python3 hivekit.py --out system.save part00.b64 part01.b64 part02.b64
    python3 hivekit.py --out sam.save sam.b64
    python3 hivekit.py --selftest
"""
import argparse
import base64
import sys

REGF = b"regf"  # every registry hive file starts with these four bytes


def strip_framing(text):
    """Drop PEM-style framing and whitespace, keep only the base64 body.
    certutil -encode wraps bytes as -----BEGIN CERTIFICATE----- ... -----END-----
    with 64-char lines; a raw base64 blob with no framing passes through too."""
    body = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("-----") and s.endswith("-----"):
            continue
        body.append(s)
    return "".join(body)


def decode_parts(texts):
    """Join the base64 bodies of each part IN THE ORDER GIVEN, then decode once.
    Parts must be concatenated before decoding, not decoded then concatenated,
    because base64 is only self-aligned on 4-char boundaries and a part may end
    mid-group. Raises ValueError on non-base64 input."""
    joined = "".join(strip_framing(t) for t in texts)
    try:
        return base64.b64decode(joined, validate=True)
    except (base64.binascii.Error, ValueError) as e:
        raise ValueError(f"not valid base64 after joining {len(texts)} part(s): {e}")


def hive_kind(data):
    """Best-effort label from the hive's embedded file name, for a friendly
    message only. The authoritative check is the regf magic, not this."""
    if len(data) < 4 or data[:4] != REGF:
        return None
    window = data[:4096].replace(b"\x00", b"").upper()
    for name in (b"SECURITY", b"SYSTEM", b"SAM"):
        if name in window:
            return name.decode()
    return "hive"


def reassemble(parts, out_path):
    try:
        data = decode_parts([open(p, "r", encoding="utf-8", errors="replace").read() for p in parts])
    except ValueError as e:
        sys.exit(f"error: {e}")
    kind = hive_kind(data)
    if kind is None:
        sys.exit(f"error: decoded {len(data)} bytes but the leading bytes are "
                 f"{data[:4]!r}, not {REGF!r}; the parts are wrong or out of order")
    with open(out_path, "wb") as fh:
        fh.write(data)
    print(f"[+] wrote {out_path}: {len(data)} bytes, looks like the {kind} hive (regf ok)")


def selftest():
    # round-trip a minimal fake "hive": regf magic + a name + padding, framed
    # the way certutil would, split across two parts at a non-aligned boundary.
    blob = REGF + b"\x00" * 8 + b"S\x00Y\x00S\x00T\x00E\x00M\x00" + b"\x00" * 64
    b64 = base64.b64encode(blob).decode()
    framed = "-----BEGIN CERTIFICATE-----\n" + "\n".join(
        b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE-----\n"
    cut = len(b64) // 2 + 1  # deliberately off a 4-char boundary
    assert decode_parts([b64[:cut], b64[cut:]]) == blob, "split-join round trip failed"
    assert decode_parts([framed]) == blob, "framing strip failed"
    assert hive_kind(blob) == "SYSTEM", "hive_kind failed"
    assert hive_kind(b"nope" + blob[4:]) is None, "magic check too loose"
    try:
        decode_parts(["this is not base64!!!"])
    except ValueError:
        pass
    else:
        raise AssertionError("bad base64 should have raised")
    print("selftest ok: join-order, framing strip, regf magic, bad-input guard")


def main():
    p = argparse.ArgumentParser(description="reassemble and validate base64-encoded registry hives (inert helper)")
    p.add_argument("parts", nargs="*", help="base64 part files, in order")
    p.add_argument("--out", help="output path for the decoded hive")
    p.add_argument("--selftest", action="store_true", help="run internal checks and exit")
    args = p.parse_args()
    if args.selftest:
        return selftest()
    if not args.parts or not args.out:
        p.error("give one or more base64 part files and --out <path> (or --selftest)")
    reassemble(args.parts, args.out)


if __name__ == "__main__":
    main()
