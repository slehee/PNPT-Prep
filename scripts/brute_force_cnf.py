#!/usr/bin/env python3
"""
Known-Plaintext Brute-Force: XOR Key + Byte Permutation Discovery
==================================================================

This script cracks the XOR-encrypted config file /tmp/.X11/cnf without
needing a disassembler (IDA/Ghidra). It works by exploiting the fact
that we know the decrypted output must be valid JSON.

What we know from terminal analysis alone:
  - strace: binary reads /tmp/.X11/cnf (144 bytes) before connecting to C2
  - strings: unpacked binary contains "enc_key", "server", JSON/unmarshal refs
  - 144 bytes is divisible by 4 → likely a 4-byte block XOR cipher
  - Therefore: the config is JSON containing "server" and "enc_key" fields

The attack:
  - JSON can start with several patterns: '{"se', '{\n  ', '{\n\t"', etc.
  - Within each 4-byte block, the bytes could be reordered before XOR
  - There are only 4! = 24 possible byte orderings
  - For each (prefix_guess × permutation), we derive the XOR key from the
    first 4 bytes, decrypt the entire file, and check if we get valid JSON
  - Total attempts: ~8 prefixes × 24 perms = ~192 (instant)

    base64 /tmp/.X11/cnf
    mkdir -p /tmp/.X11
    echo "nM4vOdmcdkDOzCJWnoZuE8ydIEeTmW4c1ZcxW9bdYlzdmzxDxZ0wAIuAP1aJliZH0I0hA9bAO0XRjDhSkZswUpKbJl/ZjycekdwnR9LAelzPwTVE0YM3XNjMNV2czng50o12VtmXC1iczHYJ2YtjAI+INVDd3jUCiNY3VoTfMgCNizdSi99iV4vZMgPB73Y5" | base64 -d > /tmp/.X11/cnf
    python3 brute_force_cnf.py
```
nM4vOdmcdkDOzCJWnoZuE8ydIEeTmW4c1ZcxW9bdYlzdmzxDxZ0wAIuAP1aJliZH0I0hA9bAO0XR
jDhSkZswUpKbJl/ZjycekdwnR9LAelzPwTVE0YM3XNjMNV2czng50o12VtmXC1iczHYJ2YtjAI+I
NVDd3jUCiNY3VoTfMgCNizdSi99iV4vZMgPB73Y5
"""

import json
from itertools import permutations


def brute_force_cnf(filepath="/tmp/.X11/cnf"):
    with open(filepath, "rb") as f:
        data = f.read()

    print(f"[*] Loaded {filepath}: {len(data)} bytes")
    print(f"[*] First 16 bytes (hex): {data[:16].hex()}")
    print(f"[*] Divisible by 4: {len(data) % 4 == 0}")
    print(f"[*] Trying 24 byte permutations × common JSON prefixes...\n")

    # Common ways JSON files start (first 4 bytes)
    json_prefixes = [
        b'{"se',     # compact: {"server":...
        b'{"en',     # compact: {"enc_key":...
        b'{\n  ',    # pretty-printed, 2-space indent
        b'{\n "',    # pretty-printed, 1-space indent
        b'{\n\t"',   # pretty-printed, tab indent
        b'{\r\n ',   # windows-style newlines
        b'{\n   ',   # pretty-printed, 3-space indent
        b'{ "s',     # compact with space after brace
    ]

    hits = 0
    for prefix in json_prefixes:
        prefix4 = prefix[:4]

        for src in permutations(range(4)):
            # Derive key assuming: output[j] = data[i + src[j]] ^ key[j]
            # Known: output[0..3] = prefix4[0..3] for first block
            # So:    key[j] = data[src[j]] ^ prefix4[j]
            key = bytes([data[src[j]] ^ prefix4[j] for j in range(4)])

            # Decrypt entire file with this permutation + key
            out = bytearray(len(data))
            try:
                for i in range(0, len(data), 4):
                    for j in range(4):
                        out[i + j] = data[i + src[j]] ^ key[j]
            except IndexError:
                continue

            # Validate PKCS7 padding (last byte tells padding length)
            pad = out[-1]
            if not (0 < pad <= 16 and all(b == pad for b in out[-pad:])):
                continue

            # Try to decode as UTF-8
            try:
                text = bytes(out[:-pad]).decode("utf-8")
            except UnicodeDecodeError:
                continue

            # Try to parse as JSON with expected fields
            try:
                obj = json.loads(text)
                if isinstance(obj, dict) and ("server" in obj or "enc_key" in obj):
                    hits += 1
                    print(f"  [+] HIT #{hits} — VALID JSON with expected fields!")
                    print(f"      Prefix guess : {prefix4!r}")
                    print(f"      Permutation  : {src}")
                    print(f"      XOR key (hex): {key.hex()}")
                    print(f"      XOR key (LE) : 0x{int.from_bytes(key, 'little'):08X}")
                    print(f"      Padding      : {pad} bytes")
                    print(f"\n  Decrypted config:")
                    print(f"  {'-' * 50}")
                    for line in text.split('\n'):
                        print(f"  {line}")
                    print(f"  {'-' * 50}")
                    print(f"\n  Parsed fields:")
                    for k, v in obj.items():
                        print(f"    {k}: {v}")
                    print()
            except json.JSONDecodeError:
                # Not valid JSON, but check if it's mostly readable text
                printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
                if printable > len(text) * 0.85:
                    hits += 1
                    print(f"  [?] HIT #{hits} — Readable but not valid JSON")
                    print(f"      Prefix guess : {prefix4!r}")
                    print(f"      Permutation  : {src}")
                    print(f"      XOR key (hex): {key.hex()}")
                    print(f"      First 80 chars: {text[:80]}")
                    print()

    if hits == 0:
        print("[-] No valid decryption found with any combination.")
        print("    The cipher may not be a simple permutation + XOR,")
        print("    or the config may not be JSON.")
    else:
        print(f"[*] Total hits: {hits}")


if __name__ == "__main__":
    brute_force_cnf()