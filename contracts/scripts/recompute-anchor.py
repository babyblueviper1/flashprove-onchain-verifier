#!/usr/bin/env python3
"""Recompute a FlashProve anchor digest from the artifact files and, optionally, compare it to an
anchored value. Standard library only; reads each file in chunks (the key and leaves are large).

  anchorDigest = SHA-256("FlashProve/anchor-v1\\0"
                         ‖ sha256(policy) ‖ sha256(layout) ‖ sha256(kl) ‖ sha256(key)
                         ‖ u32le(leafCount) ‖ sha256(leaf_0) ‖ … ‖ sha256(leaf_{n-1}))

usage: recompute-anchor.py <policy> <layout> <kl> <key> <leaf_0> [<leaf_1> ...] [--expect 0x<digest>]
Leaves are given in entry-number order. Exit 0 = recomputed (and matched, with --expect), 1 = mismatch.
"""
import hashlib
import struct
import sys

DOMAIN = b"FlashProve/anchor-v1\x00"


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def anchor_digest(policy, layout, kl, key, leaves):
    h = hashlib.sha256(DOMAIN)
    for p in (policy, layout, kl, key):
        h.update(file_sha256(p))
    h.update(struct.pack("<I", len(leaves)))
    for p in leaves:
        h.update(file_sha256(p))
    return h.digest()


def main(argv):
    expect = None
    if "--expect" in argv:
        i = argv.index("--expect")
        expect = argv[i + 1].lower().removeprefix("0x")
        argv = argv[:i] + argv[i + 2:]
    if len(argv) < 5:
        print(__doc__, file=sys.stderr)
        return 64
    got = anchor_digest(*argv[:4], argv[4:]).hex()
    print(f"anchor digest: 0x{got}")
    if expect is None:
        return 0
    if got == expect:
        print("RECOMPUTED: matches the anchored digest")
        return 0
    print(f"MISMATCH: anchored 0x{expect}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
